'''
We cleanup the report.json file, not the csv file.
We want to have it in the following format:
    Type1
        |----variable 1
        |----variable 2
        |       |--------file 1
        |       |--------file 2
        |       |           |-----vulnerability 1
        |       |           |-----vulnerability 2
        |       |           |           |-----trace
        |       |           |-----.......
        |       |           |-----vulnerability X
        |       |--------....
        |       |--------file X
        |----....
        |----variable X
    Type 2
    .....
    
with Type= {"nodeType": "vulnType","name": type, "children": [] => list of variables}
with variable= {"nodeType": "var","name": source, "children":[] => list of files}
with file= {"nodeType": "file","name": filename, "children":[]=> list of vulnerabilities}
with vulnerabilty= {"nodeType": "vuln","line":line,"name": variable_name, "snippet": snippet,"trace":[]=> list of trace}
with trace= {"label": label, "file": filename, "line": line}
'''
import argparse
import json
import sys
import time

listOnly=["missingAccessControl"]

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn script to clean and reorganize the report for better output.")
    # Required positional argument
    parser.add_argument("out_json", help="The path of the .json file with the report.")
    args= parser.parse_args()
    return args.out_json

def getTypes(content):
    try:
        types=[]
        for entry in content:
            if entry["type"] not in types:
                types.append(entry["type"])
        return [ {"nodeType": "vulnType", "name":t,"children":[]} for t in types]
    except Exception as e:
        print(f"An error occured while parsing JSON: {e}")
        return None
    
def addVulnToReport(vuln,report):
    try:
        vulnType= vuln["type"]
        variable= vuln["variable"]
        fileName= vuln["file"]
        line= vuln["line"]
        snippet= vuln["snippet"]
        source= vuln["source"]
        trace= vuln["trace"]
        
        for entry in report:
            if entry["nodeType"]=="vulnType" and entry["name"]==vulnType:
                if vulnType in listOnly:
                    # we only want to have it in a list
                    if fileName not in entry["children"]:
                        entry["children"].append(fileName)
                    return True

                # find or create the var node
                foundVar = next((child for child in entry["children"] if child["nodeType"]=="var" and child["name"]==source), None)
                if foundVar is None:
                    foundVar = {"nodeType": "var", "name": source, "children": []}
                    entry["children"].append(foundVar)

                # find or create the file node
                foundFile = next((child for child in foundVar["children"] if child["nodeType"]=="file" and child["name"]==fileName), None)
                if foundFile is None:
                    foundFile = {"nodeType": "file", "name": fileName, "children": []}
                    foundVar["children"].append(foundFile)

                # add vuln if not duplicate
                newvuln = {"nodeType": "vuln", "name": variable, "snippet": snippet, "line": line, "trace": trace}
                duplicate = next((child for child in foundFile["children"] if child["nodeType"]==newvuln["nodeType"] and child["name"]==newvuln["name"] and child["snippet"]==newvuln["snippet"] and child["line"]==newvuln["line"]), None)
                if duplicate is None:
                    foundFile["children"].append(newvuln)
                return True

        print(f"An error occured while adding vulnerability {vuln} to report: vulnType '{vulnType}' not found in report")
        return False
    except Exception as e:
        print(f"An error occured while adding vulnerability {vuln} to report: {e}")
        return False

outJson=parseArgs()
try:
    f= open(outJson,"r")
    report= json.load(f)
    f.close()
except Exception as e:
    print(f"An error ocurred while trying to read {outJson}: {e}")
    sys.exit(1)
    
initialReport=getTypes(report)
if initialReport is None:
    sys.exit(1)
    
for vuln in report:
    if not addVulnToReport(vuln,initialReport):
        sys.exit(1)

try:
    f= open(outJson,"w")
    json.dump(initialReport,f,indent=2)
    f.close()
except Exception as e:
    print(f"An error ocurred while trying to write to {outJson}: {e}")
    sys.exit(1)
    
sys.exit(0)