import argparse
import sys
import shutil
import os
import json
import subprocess
from pathlib import Path

CONFIG_FILE= "phpwn.config.json"

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn main script.")
    # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    # Optional flags
    parser.add_argument("--configure", "-c", action="store_true", help="Pass this if you have a project without phpwn config file and want to create one.")
    args= parser.parse_args()
    return args.src_dir,args.configure

def parseConfig(srcDir):
    try:
        f= open(os.path.join(srcDir,CONFIG_FILE),"r")
        content= json.load(f)
        f.close()
        return content
    except Exception as e:
        print(f"An error ocurred while parsing {CONFIG_FILE}: {e}")
        return None

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
    
def main():
    srcDir,configure= parseArgs()
    currentDir=os.path.dirname(os.path.abspath(__file__))
    if configure:
        print(f"[+] Copying configuration file: {CONFIG_FILE}")
        try:
            shutil.copy2(os.path.join(currentDir,"Templates/phpwn.config.json"), os.path.join(srcDir,CONFIG_FILE))
        except Exception as e:
            print(f"[!] Error copying {CONFIG_FILE} file: {e}")
            return False
        return True
    else:
        if not os.path.exists(os.path.join(srcDir,CONFIG_FILE)):
            print(f"[!] File {CONFIG_FILE} not found in {srcDir}. Please run --configure first.")
            return True
        config=parseConfig(srcDir)
        if config is None:
            return False
        srcDirAbs= Path(os.path.realpath(os.path.join(currentDir,srcDir,config["target"]))).absolute()
        outDirAbs=Path(os.path.realpath(os.path.join(currentDir,srcDir,config["outputDir"]))).absolute()
        varsFileAbs=Path(os.path.realpath(os.path.join(currentDir,srcDir,config["variablesFile"]))).absolute()
        if not runCommandOrFail([sys.executable, "wrapper.py", srcDirAbs,outDirAbs,"--excludes",*config["excludes"],"--vars-file",varsFileAbs,"--output-json",config["outputJson"],"--output-csv",config["outputCsv"]]+(["--direct-serving"] if config["directServing"] else []),os.getcwd()):
            print(f"[!] An error ocurred while calling wrapper.py")
            return False 
    
if __name__=="__main__":
    if main():
        print(f"[+] Done")
        sys.exit(0)
    sys.exit(1)