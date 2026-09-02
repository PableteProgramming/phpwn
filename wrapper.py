import argparse
import subprocess
import os
import sys
import json

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn wrapper script.")
    # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    parser.add_argument("out_dir", help="The output directory.")
    # Optional flags
    parser.add_argument("--excludes", "-e", nargs="+", default=[], help="Directories to skip.")
    parser.add_argument("--vars-file","-v",type=str,default="phpwn.vars.json", help="The path of the file with the variables.")
    parser.add_argument("--output-json", "-j", type=str, default="result.json", help="Report filename for json format")
    parser.add_argument("--output-csv", "-c", type=str, default="result.csv", help="Report filename for CSV format")
    parser.add_argument("--direct-serving", "-d", action="store_true", help="If the files are directly served on production. For accessible files check.")
    parser.add_argument("--htaccess-path","-H",type=str, default=".htaccess", help="The path of the .htaccess file from the root dir.")
    parser.add_argument("--accessible-files","-a",action="store_true",help="Pass this if you want PHPwn to check for accessbile files based on an .htaccess routing file.")
    args= parser.parse_args()
    return args.src_dir,args.out_dir,args.excludes,args.vars_file,args.output_json,args.output_csv,args.direct_serving,args.htaccess_path,args.accessible_files

def runCommandOrFail(command,wd,allowCodes=[0],output=False):
    try:
        result= subprocess.run(command,cwd=wd,capture_output=True,text=True)
        if result.returncode not in allowCodes:
            print(f"STDOUT:\n {result.stdout}\n"+"-"*20)
            print(f"STDERR:\n {result.stderr}\n"+"-"*20)
            print(f"RETURN CODE: {result.returncode}"+"-"*20)
            if output:
                return False,""
            else:
                return False
        if output:
            return True,result.stdout
        else:
            return True
    except FileNotFoundError:
        print(f"[!] {command[0]} not found !")
        if output:
            return False,""
        else:
            return False
    
def updateChildren(content,xss,sql): # because content is a list, it is passed as reference ! xD
    content["taint"]["xss"]=xss
    content["taint"]["sql"]=sql
    if not (xss is None and sql is None):
        if isinstance(content["children"],dict):
            for child in content["children"].values():
                updateChildren(child,xss,sql)
            
def visitNode(node,safeL,xssL,sqlL):
    if node["taint"]["xss"] is False and node["taint"]["sql"] is False:
        safeL.append(node["name"])
    if node["taint"]["xss"] is True:
        xssL.append(node["name"])
    if node["taint"]["sql"] is True:
        sqlL.append(node["name"])
    # we now visit the children
    if isinstance(node["children"],dict):
        for child in node["children"].values():
            safeL,xssL,sqlL= visitNode(child,safeL,xssL,sqlL)
    return safeL,xssL,sqlL
    
def buildVarsList(varsFile):
    try:
        safeVars=[]
        xssVars=[]
        sqlVars=[]
        f= open(varsFile,"r")
        content=json.load(f)
        f.close()
        if not  isinstance(content,dict):
            if isinstance(content,list) and len(content)<=0:
                return True,[],[],[]
            return False,[],[],[]
        for var in content.values():
            updateChildren(var,var["taint"]["xss"],var["taint"]["sql"])
        # Now we updated the children ! We may write this back to the file so that the user sees what happened
        f=open(varsFile,"w")
        json.dump(content,f)
        f.close()
        # Now, we can build the arrays needed !
        for var in content.values():
            safeVars,xssVars,sqlVars= visitNode(var,safeVars,xssVars,sqlVars)                
        return True,safeVars,xssVars,sqlVars
    except Exception as e:
        print(f"[!] An error ocurred while trying to parse the vars file {varsFile}: {e}")
        return False,[],[],[]

def main():
    srcDir,outDir,excludes,varsFile,outputJson,outputCsv,directServing,htaccessPath,accessibleFiles= parseArgs()
    currentDir=os.path.dirname(os.path.abspath(__file__))

    if not os.path.exists(varsFile):
        # if the file is not existing yet, we need to create it, and let the user choose.
        print("[+] Running variables setup...")
        if not runCommandOrFail([sys.executable, "setup.py", srcDir,outDir,]+(["--excludes",*excludes] if len(excludes)>0 else [])+["--vars","--vars-file",varsFile],currentDir):
            print("[!] An error ocurred during setup. Exiting...")
            return False
        return None # not true, because variables config

    ok,safeVars,xssVars,SqlVars= buildVarsList(varsFile)
    if not ok:
        return False

    print("[+] Setting up PHPwn...")
    if not runCommandOrFail([sys.executable, "setup.py", srcDir,outDir]+(["--excludes",*excludes] if len(excludes)>0 else [])+(["--safe-patterns",*safeVars] if len(safeVars)>0 else [])+(["--xss-patterns",*xssVars] if len(xssVars)>0 else [])+(["--sql-patterns",*SqlVars] if len(SqlVars)>0 else [])+(["--accessible-files"] if accessibleFiles else []),currentDir):
        print("[!] An error ocurred during setup. Exiting...")
        return False
    print("[+] Starting analysis. This may take a while...")
    if not runCommandOrFail([sys.executable, "run.py", srcDir,outDir,"--output-json",outputJson,"--output-csv",outputCsv]+(["--direct-serving"] if directServing else [])+(["--accessible-files", "--htaccess-path", htaccessPath] if accessibleFiles else []),currentDir):
        print("[!] An error ocurred during analysis. Exiting...")
        return False
    print("[+] Analysis done !")
    return True

if __name__=="__main__":
    code=main()
    if code==True:
        sys.exit(0)
    elif code is None:
        sys.exit(2)
    sys.exit(1)
