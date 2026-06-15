import json
from abc import ABC, abstractmethod
import csv
import io
import argparse
import os
import sys
from pathlib import Path

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn report script.")
    # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    parser.add_argument("psalm_output", help="The filename of the psalm results.")
    parser.add_argument("phpstan_output", help="The filename of the phpstan results.")
    parser.add_argument("codechecker_output", help="The filename of the codebaseChecker results.")
    # Optional flags
    parser.add_argument("--output-json", "-j", type=str, default="result.json", help="Report filename for json format")
    parser.add_argument("--output-csv", "-c", type=str, default="result.csv", help="Report filename for CSV format")
    args= parser.parse_args()
    return args.src_dir,args.psalm_output,args.phpstan_output,args.codechecker_output,args.output_json,args.output_csv

# Each Report type must implement the report method.
class Report(ABC):
    @abstractmethod
    def report(self):
        pass

# This class reports the file that are accessible and not guarded.
class AccessibleFilesReport(Report):
    def __init__(self,phpstanPath,codeCheckerPath,srcDir):
        self.phpstanPath=phpstanPath
        self.codeCheckerPath=codeCheckerPath
        self.srcDir=srcDir
        
    def report(self):
        try:
            f= open(self.phpstanPath)
            phpstanOutput= json.load(f)
            f.close()
        except Exception as e:
            print(f"An error ocurred while trying to read {self.phpstanPath}: {e}")
            return None

        try:
            f= open(self.codeCheckerPath)
            codeCheckerOutput= json.load(f)
            f.close()
        except Exception as e:
            print(f"An error ocurred while trying to read {self.codeCheckerPath}: {e}")
            return None
        
        missingguardFiles=[]
        for filename, data in phpstanOutput["files"].items():
            for message in data["messages"]:
                if(message["identifier"]=="security.missingGuard"):
                    missingguardFiles.append(filename.strip())
        
        missingguardFiles= list(set(missingguardFiles))
        missingguardFiles= [Path(f).resolve() for f in missingguardFiles]
        
        intersection=[]
        for file in codeCheckerOutput["accessible_files"]:
            file=file.strip()
            if Path(file).resolve() in missingguardFiles:
                intersection.append(file)
        relDir= os.path.join(os.getcwd(),os.path.basename(os.path.normpath(self.srcDir)))
        intersection= [os.path.relpath(f, start=relDir) for f in intersection]
        output=[]
        for file in intersection:
            output.append({"type": "missingAccessControl","file": file,"line": "","snippet": "","source": "","variable":"","trace": []})
        return output
    
# This class is a wrapper for Psalm reports
# the only thing to change is the types you want to handle
class PsalmReport(Report):
    def __init__(self,psalmOutputPath):
        self.psalmOutputPath=psalmOutputPath
        self.types=None
        self.vulnClass=None
        
    def __private_buildTrace(self,error):
        trace={}
        for traceEntry in error["taint_trace"]:
            try:
                label=traceEntry['label']
                file=traceEntry['file_name']
                line=traceEntry['line_from']
                
                # the key avoids having noisy duplicates
                key=(file,line)
                if key not in trace:
                    trace[key]=label
            except:
                # some traces doesn't have a file_name property, just entry_path_type
                # we skip it
                continue
        
        output=[]
        for (file,line),label in trace.items():
            output.append({"label":label,"file":file,"line":line})
        return output
        
    def report(self):
        try:
            f= open(self.psalmOutputPath)
            psalmOutput= json.load(f)
            f.close()
        except Exception as e:
            print(f"An error ocurred while trying to read {self.psalmOutputPath}: {e}")
            return None
        
        output=[]
        for error in psalmOutput:
            if error["type"] in self.types:
                trace= self.__private_buildTrace(error)
                if trace:
                    obj= {
                        "type": self.vulnClass.strip(),
                        "file":error["file_name"].strip(),
                        "line":error["line_from"],
                        "snippet":error["snippet"].strip(),
                        "source":trace[0]["label"],
                        "variable":trace[-1]["label"],
                        "trace":trace,
                    }
                    output.append(obj)
        return output
        
# This handle vulnerabilities of type "TaintedSql"
class SQLIReport(PsalmReport):
    def __init__(self,p):
        super().__init__(p)
        self.types=["TaintedSql"]
        self.vulnClass="SQLI"
        
# This one handles vulnerabilities of type "TaintedHtml" for now
class XSSReport(PsalmReport):
    def __init__(self,p):
        super().__init__(p)
        self.types=["TaintedHtml","TaintedTextWithQuotes"]
        self.vulnClass="XSS"
    
# This class does a report of all errors: MissingGaurds, XSS and SQLI
# We need this custom class so that the format, for example trace number match in case of formatting with csv
class FullReport(Report):
    def __init__(self,srcDir,phpStanOutput,psalmOutput,codeCheckerOutput):
        self.phpStanOutput=phpStanOutput
        self.psalmOutput=psalmOutput
        self.codeCheckerOutput=codeCheckerOutput
        self.srcDir=srcDir
        
    def report(self):
        accessibleFiles=AccessibleFilesReport(self.phpStanOutput,self.codeCheckerOutput,self.srcDir).report()
        sqliOutput=SQLIReport(self.psalmOutput).report()
        xssOutput=XSSReport(self.psalmOutput).report()
        if accessibleFiles is None or sqliOutput is None or xssOutput is None:
            return None
        return accessibleFiles+sqliOutput+xssOutput
    
# This class formats the output of the reports for user readability
class Formatter:
    def __init__(self,type):
        self.type=type
        
    def format(self,input,file=None):
        if self.type=="json":
            if file:
                try:
                    f= open(file,"w")
                    f.write(json.dumps(input,indent=2))
                    f.close()
                    return True,""
                except Exception as e:
                    return False,f"An error ocurred while opening/writing to {file}: {e}"
            else:
                try:
                    return True,json.dumps(input,indent=2)
                except:
                    return False,"An error ocurred while parsing it to json"
        elif self.type=="csv":
            if file:
                f= open(file,"w",newline="")
            else:
                f= io.StringIO()
            try:
                writer = csv.writer(f)
                
                # we calculate the number of columns necessary for the traces
                maxTraces= max(len(entry["trace"]) for entry in input)
                headers= ["type", "file", "line", "snippet", "source", "variable"] + [f"trace_{i+1}" for i in range(maxTraces)]
                # we write the header
                writer.writerow(headers)
                
                # we now write the errors
                for error in input:
                    traces = [f"{trace['label']} @ {trace['file']}:{trace['line']}" for trace in error["trace"]]+ [""]*(maxTraces-len(error["trace"]))
                    row= [error["type"], error["file"], error["line"], error["snippet"], error["source"], error["variable"],*traces]
                    writer.writerow(row)
            except Exception as e:
                if file:
                    return False,f"An error ocurred while opening/writing to {file}: {e}"
                else:
                    return False,f"An error ocurred while parsing csv: {e}"
            if file:
                f.close()
                return True,""
            else:
                return True,f.getvalue()
        else:
            return False,f"Format {self.type} not supported !"

def cleanReport(content):
    try:
        # for finding duplicates, we created a four ways key (vulnType,file,line,source-variable)
        seen={}
        for vuln in content:
            # we remove all the "call to ..." as a source, it is irrelevant and makes noise
            if not vuln["source"].startswith("call to"):
                key=(vuln["type"],vuln["file"],vuln["line"],vuln["source"])
                if key not in seen:
                    seen[key]=vuln
        return list(seen.values())
    except Exception as e:
        print(f"An error ocurred while trying to parse the report's content: {e}")
        return None
     
SRC_DIR,PSALM_OUTPUT,PHPSTAN_OUTPUT,CODECHECKER_OUTPUT,OUTPUT_JSON,OUTPUT_CSV=parseArgs()
report= FullReport(SRC_DIR,PHPSTAN_OUTPUT,PSALM_OUTPUT,CODECHECKER_OUTPUT).report()
if report is None:
    print("An error ocurred while doing the full report.")
    sys.exit(1)
    
#clean=cleanReport(report)
#if clean is None:
#    print(f"An error ocurred while cleaning up report")
#    sys.exit(1)

#r,_=Formatter("json").format(clean,OUTPUT_JSON)
r,_=Formatter("json").format(report,OUTPUT_JSON)
if not r:
    print(f"An error ocurred while formatting output to {OUTPUT_JSON}")
    sys.exit(1)
    
r,_=Formatter("csv").format(report,OUTPUT_CSV)
if not r:
    print(f"An error ocurred while formatting output to {OUTPUT_CSV}")
    sys.exit(1)

    
sys.exit(0)