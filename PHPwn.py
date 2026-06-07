import argparse
import subprocess
import os
import sys

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn main script.")
    # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    parser.add_argument("out_dir", help="The output directory.")
    # Optional flags
    parser.add_argument("--excludes", "-e", nargs="+", default=[], help="Directories to skip.")
    parser.add_argument("--safe-patterns", "-s", nargs="+", default=[], help="Patterns for safe variables.")
    parser.add_argument("--input-patterns", "-i", nargs="+", default=[], help="Patterns for input variables.")
    parser.add_argument("--output-json", "-j", type=str, default="result.json", help="Report filename for json format")
    parser.add_argument("--output-csv", "-c", type=str, default="result.csv", help="Report filename for CSV format")
    parser.add_argument("--direct-serving", "-d", action="store_true", help="If the files are directly served on production. For accessible files check.")
    args= parser.parse_args()
    return args.src_dir,args.out_dir,args.excludes,args.safe_patterns,args.input_patterns,args.output_json,args.output_csv,args.direct_serving

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

def main():
    srcDir,outDir,excludes,safePatterns,inputPatterns,outputJson,outputCsv,directServing= parseArgs()
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
