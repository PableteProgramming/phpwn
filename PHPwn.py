import argparse
import subprocess
import os
import sys
import json

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn main script.")
    # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    parser.add_argument("out_dir", help="The output directory.")
    # Optional flags
    parser.add_argument("--excludes", "-e", nargs="+", default=[], help="Directories to skip.")
    parser.add_argument("--vars-file","-v",type=str,default="phpwn.vars.json", help="The path of the file with the variables.")
    parser.add_argument("--output-json", "-j", type=str, default="result.json", help="Report filename for json format")
    parser.add_argument("--output-csv", "-c", type=str, default="result.csv", help="Report filename for CSV format")
    parser.add_argument("--direct-serving", "-d", action="store_true", help="If the files are directly served on production. For accessible files check.")
    args= parser.parse_args()
    return args.src_dir,args.out_dir,args.excludes,args.vars_file,args.output_json,args.output_csv,args.direct_serving

def runCommandOrFail(command,wd,allowCodes=[0]):
    try:
        result= subprocess.run(command,cwd=wd,capture_output=True,text=True)
        if result.returncode not in allowCodes:
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            print(f"return code: {result.returncode}")
            return False
        return True
    except FileNotFoundError:
        print(f"[!] {command[0]} not found !")
        return False

def buildPatternsList(varsFile):
    try:
        safePatterns=[]
        inputPatterns=[]
        f= open(varsFile,"r")
        content=json.load(f)
        for var in content:
            if var["type"]=="safe":
                safePatterns.append(var["name"])
            elif var["type"]=="unknown" or var["type"]=="input":
                inputPatterns.append(var["name"])
            else:
                print(f"You have a variable that has a type other than (safe, input, unknown): {var['type']}")
                return False,[],[]
        return True,safePatterns,inputPatterns
    except Exception as e:
        print(f"An error ocurred while trying to parse the vars file {varsFile}: {e}")
        return False,[],[]

def main():
    srcDir,outDir,excludes,varsFile,outputJson,outputCsv,directServing= parseArgs()
    
    if not os.path.exists(varsFile):
        # if the file is not existing yet, we need to create it, and let the user choose.
        print("[+] Running variables setup...")
        if not runCommandOrFail([sys.executable, "setup.py", srcDir,outDir,"--excludes",*excludes,"--vars","--vars-file",varsFile],os.getcwd()):
            print("An error ocurred during setup. Exiting...")
            return False
        return True

    ok,safePatterns,inputPatterns= buildPatternsList(varsFile)
    if not ok:
        return False
    
    print("[+] Setting up PHPwn...")
    if not runCommandOrFail([sys.executable, "setup.py", srcDir,outDir,"--excludes",*excludes,"--safe-patterns",*safePatterns,"--input-patterns",*inputPatterns],os.getcwd()):
        print("An error ocurred during setup. Exiting...")
        return False
    print("[+] Starting analysis. This may take a while...")
    if not runCommandOrFail([sys.executable, "run.py", srcDir,outDir,"--output-json",outputJson,"--output-csv",outputCsv]+(["--direct-serving"] if directServing else []),os.getcwd()):
        print("An error ocurred during analysis. Exiting...")
        return False
    print("[+] Analysis done !")
    return True

if __name__=="__main__":
    if main():
        sys.exit(0)
    sys.exit(1)
