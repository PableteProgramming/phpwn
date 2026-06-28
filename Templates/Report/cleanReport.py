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
with variable= {"nodeType": "var","name": variable name, "children":[] => list of files}
with file= {"nodeType": "file","name": filename, "children":[]=> list of vulnerabilities}
with vulnerabilty= {"nodeType": "vuln","name": source, "snippet": snippet,"trace":[]=> list of trace}
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
        
        done=False
        for entry in report:
            if entry["nodeType"]=="vulnType" and entry["name"]==vulnType:
                if vulnType in listOnly:
                    # we only want to have it in a list
                    if fileName not in entry["children"]:
                        entry["children"].append(fileName)
                    done=True
                    break
                # we found the vulnerabilty type we want to add
                foundVar= None
                for var in entry["children"]:
                    if var["nodeType"]=="var" and var["name"]==variable:
                        foundVar=var
                        break
                if foundVar is None:
                    # we need to create such an entry
                    foundVar={"nodeType":"var","name":variable,"children":[]}
                    entry["children"].append(foundVar)
                    foundVar= next((child for child in entry["children"] if child["name"]==variable),None)
                # we now have foundVar
                if foundVar is None:
                    e="Couldn't add the children with variable name "+variable
                    break
                # we added the variable sucessfully, we go for the next step
                foundFile= None
                for file in foundVar["children"]:
                    if file["nodeType"]=="file" and file["name"]==fileName:
                        foundFile=file
                        break
                if foundFile is None:
                    # we need to create such an entry
                    foundFile={"nodeType":"file","name":fileName,"children":[]}
                    foundVar["children"].append(foundFile)
                    foundFile= next((child for child in foundVar["children"] if child["name"]==fileName),None)
                # we now have foundFile
                if foundFile is None:
                    e="Couldn't add the children with file name "+fileName
                    break
                # we added the file sucessfully, we go for the next step
                newvuln={"nodeType":"vuln","name":source,"snippet":snippet,"line":line,"trace":trace}
                duplicate=next((child for child in foundFile["children"] if child["nodeType"]==newvuln["nodeType"] and child["name"]==newvuln["name"] and child["snippet"]==newvuln["snippet"] and child["line"]==newvuln["line"]),None)
                if duplicate is None:
                    # we can add this
                    foundFile["children"].append(newvuln)
                done=True
        if not done:
            print(f"An error occured while adding vulnerability {vuln} to report: {e}")
            return False
        return True
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