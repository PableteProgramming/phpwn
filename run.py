'''
This script runs Psalm and PHPStan and analyzes their output to create a report
setup.py needs to be ran before !
This script does the following steps:
    - Run Psalm
    - Run PHPStan
    - Run the custom codebasechecker script
    - Run report.py
'''
import argparse
import subprocess
import os
import json
import shutil

PSALM_OUTPUT="psalm-results.json"
PHPSTAN_OUTPUT="phpstan-results.json"
CODEBASECHECK_OUTPUT="codebaseCheck.json"

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn run script.")
     # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    parser.add_argument("out_dir", help="The output directory.")
    # Optional flags
    parser.add_argument("--output-json", "-j", type=str, default="result.json", help="Report filename for json format")
    parser.add_argument("--output-csv", "-c", type=str, default="result.csv", help="Report filename for CSV format")
    parser.add_argument("--direct-serving", "-d", action="store_true", help="If the files are directly served on production. For accessible files check.")
    args= parser.parse_args()
    return args.src_dir,args.out_dir,args.output_json,args.output_csv,args.direct_serving

def runCommand(command,wd):
    try:
        result= subprocess.run(command,cwd=wd,capture_output=True,text=True)
    except FileNotFoundError:
        print(f"[!] {command[0]} not found !")
        return None,None
    return "" if not result.stdout else result.stdout, "" if not result.stderr else result.stderr


def run():
    srcDir,outDir,outputJson,outputCsv,directServing= parseArgs()
    srcPath= os.path.join(outDir,os.path.basename(srcDir))
    
    print("[+] Running Psalm. This may take a while...")
    out,err=runCommand(["vendor/bin/psalm", "--taint-analysis", "--no-cache","--output-format=json"],srcPath)
    if out is None and err is None:
        return False
    
    try:
        if os.path.exists(os.path.join(outDir,PSALM_OUTPUT)):
            os.remove(os.path.join(outDir,PSALM_OUTPUT))
        f= open(os.path.join(outDir,PSALM_OUTPUT),"w")
        json.dump(json.loads(out),f,indent=2)
        f.close()
    except Exception as e:
        print(f"An error ocurred while trying to store the results of psalm in {PSALM_OUTPUT}: {e}")
        return False
    
    print("[+] Running PHPStan. This may take a while...")
    out,err=runCommand(["vendor/bin/phpstan", "analyse", "--no-progress","--error-format=json"],srcPath)
    if out is None and err is None:
        return False
    
    try:
        if os.path.exists(os.path.join(outDir,PHPSTAN_OUTPUT)):
            os.remove(os.path.join(outDir,PHPSTAN_OUTPUT))
        f= open(os.path.join(outDir,PHPSTAN_OUTPUT),"w")
        json.dump(json.loads(out),f,indent=2)
        f.close()
    except Exception as e:
        print(f"An error ocurred while trying to store the results of PHPStan in {PHPSTAN_OUTPUT}: {e}")
        return False
    
    print("[+] Running codebaseCheck. This may take a while...")
    out,err=runCommand(["python3", "codebaseCheck.py", ".htaccess",".","--format=json"]+(["--direct-serving"] if directServing else []),srcPath)
    if out is None and err is None:
        return False
    
    try:
        if os.path.exists(os.path.join(outDir,CODEBASECHECK_OUTPUT)):
            os.remove(os.path.join(outDir,CODEBASECHECK_OUTPUT))
        f= open(os.path.join(outDir,CODEBASECHECK_OUTPUT),"w")
        json.dump(json.loads(out),f,indent=2)
        f.close()
    except Exception as e:
        print(f"An error ocurred while trying to store the results of codebaseCheck in {CODEBASECHECK_OUTPUT}: {e}")
        return False
        
    try:
        shutil.rmtree(srcPath)
    except FileNotFoundError as e:
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
        
    print("[+] Running report.py. This may take a while...")
    out,err=runCommand(["python3", "report.py", srcDir,PSALM_OUTPUT,PHPSTAN_OUTPUT,CODEBASECHECK_OUTPUT,"--output-json",outputJson,"--output-csv",outputCsv],outDir)
    if out is None and err is None:
        return False
    
    try:
        os.remove(os.path.join(outDir,CODEBASECHECK_OUTPUT))
        os.remove(os.path.join(outDir,PSALM_OUTPUT))
        os.remove(os.path.join(outDir,PHPSTAN_OUTPUT))
        os.remove(os.path.join(outDir,"report.py"))
    except Exception as e:
        print("An error ocurred while cleaning up.")
        return False
        
    return True
    
if __name__=="__main__":
    if run():
        print(f"Analysis finished. Look at the output files !")
    else:
        print("An error ocurred during Analysis.")