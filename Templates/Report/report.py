import json
from abc import ABC, abstractmethod
import csv
import io
import argparse
import os

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

# Each Report type must implement the report and __str__ method.
class Report(ABC):
    @abstractmethod
    def report(self):
        pass
    
    @abstractmethod
    def __str__(self):
        pass

# This class reports the file that are accessible and not guarded, this can be dangerous !!!
class AccessibleFilesReport(Report):
    def __init__(self,phpstanPath,codeCheckerPath,baseName):
        self.phpstanPath=phpstanPath
        self.codeCheckerPath=codeCheckerPath
        self.baseName=baseName
        self.__output=None
        
    def report(self):
        try:
            f= open(self.phpstanPath)
            phpstanOutput= json.load(f)
            f.close()
        except:
            print(f"An error ocurred while trying to read {self.phpstanPath}")
            return None

        try:
            f= open(self.codeCheckerPath)
            codeCheckerOutput= json.load(f)
            f.close()
        except:
            print(f"An error ocurred while trying to read {self.codeCheckerPath}")
            return None
        
        missingguardFiles=[]
        for filename, data in phpstanOutput["files"].items():
            for message in data["messages"]:
                if(message["identifier"]=="security.missingGuard"):
                    if self.baseName in filename:
                        # we only want the relative path to be able to compare it to the other output
                        missingguardFiles.append(filename.split(self.baseName)[1].strip())
                    else:
                        missingguardFiles.append(filename.strip())
        
        missingguardFiles= list(set(missingguardFiles))
        
        intersection=[]
        for file in codeCheckerOutput["accessible_files"]:
            file=file.strip()
            if file in missingguardFiles:
                intersection.append(file)
        output=[]
        for file in intersection:
            output.append({"type": "accessibleNotGuarded","file": file,"line": "","snippet": "","source": "","variable":"","trace": []})
        self.__output=output
        return output
    
    def __str__(self):
        s=""
        if self.__output:
            s+="Accessible files not guarded:\n"
            for f in self.__output:
                s+=f"\t{f}\n"
        return s.strip()
    
# This class is a wrapper for Psalm reports
# the only thing to change is the types you want to handle
class PsalmReport(Report):
    def __init__(self,psalmOutputPath):
        self.psalmOutputPath=psalmOutputPath
        self.__output=None
        self.types=None
        
    def __private_buildTrace(self,error):
        trace={}
        for traceEntry in error["taint_trace"]:
            try:
                if traceEntry["label"].startswith("call to"):
                    # we skip redundant entries like "call to"
                    continue
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
        self.__output=output
        return output
        
    def report(self):
        try:
            f= open(self.psalmOutputPath)
            psalmOutput= json.load(f)
            f.close()
        except:
            print(f"An error ocurred while trying to read {self.psalmOutputPath}")
            return None
        
        output=[]
        for error in psalmOutput:
            if error["type"] in self.types:
                trace= self.__private_buildTrace(error)
                obj= {
                    "type": error["type"].strip(),
                    "file":error["file_name"].strip(),
                    "line":error["line_from"],
                    "snippet":error["snippet"].strip(),
                    "source":trace[0]["label"],
                    "variable":trace[-1]["label"],
                    "trace":trace,
                }
                output.append(obj)
        self.__output=output
        return output
            
    def __str__(self):
        s=""
        if self.__output:
            s+="Psalm SQLI errors:\n"
            for error in self.__output:
                s+=json.dumps(error,indent=2)
        return s.strip()
        
# This handle vulnerabilities of type "TaintedSql"
class SQLIReport(PsalmReport):
    def __init__(self,p):
        super().__init__(p)
        self.types=["TaintedSql"]
        
# This one handles vulnerabilities of type "TaintedHtml" for now
class XSSReport(PsalmReport):
    def __init__(self,p):
        super().__init__(p)
        self.types=["TaintedHtml","TaintedTextWithQuotes"]
    
# This class does a report of all errors: MissingGaurds, XSS and SQLI
# We need this custom class so that the format, for example trace number match in case of formatting with csv
class FullReport(Report):
    def __init__(self,phpStanOutput,psalmOutput,codeCheckerOutput,baseName):
        self.__output=None
        self.phpStanOutput=phpStanOutput
        self.psalmOutput=psalmOutput
        self.codeCheckerOutput=codeCheckerOutput
        self.baseName=baseName
        
    def report(self):
        accessibleFiles=AccessibleFilesReport(self.phpStanOutput,self.codeCheckerOutput,self.baseName).report()
        sqliOutput=SQLIReport(self.psalmOutput).report()
        xssOutput=XSSReport(self.psalmOutput).report()
        
        if not accessibleFiles:
            accessibleFiles=[]
        if not sqliOutput:
            sqliOutput=[]
        if not xssOutput:
            xssOutput=[]
        self.__output= accessibleFiles+sqliOutput+xssOutput
        return self.__output
    
    def __str__(self):
        if self.__output:
            return json.dumps(self.__output)
        return ""
    

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
                try:
                    f= open(file,"w",newline="")
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
                    f.close()
                    return True,""
                except Exception as e:
                    return False,f"An error ocurred while opening/writing to {file}: {e}"
            else:
                try:
                    f= io.StringIO()
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
                    return True,f.getvalue()
                except Exception as e:
                    return False, "An error ocurred while converting it to CSV"
        else:
            return False,f"Format {self.type} not supported !"
            

SRC_DIR,PSALM_OUTPUT,PHPSTAN_OUTPUT,CODECHECKER_OUTPUT,OUTPUT_JSON,OUTPUT_CSV=parseArgs()
BASENAME=os.path.basename(SRC_DIR)
report= FullReport(PHPSTAN_OUTPUT,PSALM_OUTPUT,CODECHECKER_OUTPUT,BASENAME).report()
Formatter("csv").format(report,OUTPUT_CSV)
Formatter("json").format(report,OUTPUT_JSON)