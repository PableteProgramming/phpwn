import sys
import re
import os
from pathlib import Path
import json
import argparse

class Formatter:
    def format(self,f,l:list):
        if f=="json":
            return True,json.dumps({"accessible_files":l},indent=2)
        elif f=="text":
            return True,f"{l}"
        else:
            return False,f"Output format {f} not supported !"

'''
This class Parses the .htaccess files to build two arrays
- blocked, which is an array containing the patterns (regex) that are blocked
- accessible, which is an array containing the paths of the files that are accessible
'''
class Parser:
    def __init__(self,filepath):
        self.filepath=filepath
        self.rulesParser={
            "RewriteBase":self.rewriteBaseRule,
            "RewriteRule":self.rewriteRuleRule,
            "DirectoryIndex":self.directoryIndexRule,
            "RedirectMatch":self.redirectMatchRule,
        }
        self.rewriteBase="/" # default
        self.blocked=[]
        self.accessible=[]
        self.dirIndex=None
        
    def rewriteBaseRule(self,line):
        parts=line.split()
        if len(parts)>1:
            self.rewriteBase=parts[1]
    
    def rewriteRuleRule(self,line):
        def parseFlags(flags):
            flags=flags.strip()
            if re.match(r'\[[A-Z0-9=,]+\]',flags):
                flags= flags[1:-1]
                f= flags.split(",")
                if "F" in f or "R=403" in f:
                    return True
            return False
            
        parts=line.split()
        if len(parts)>3:
            target=parts[2].strip()
            if target=="-" or target=='"-"':
                if parseFlags(parts[3]):
                    # we have a blocked pattern
                    self.blocked.append(parts[1])
            else:
                # we check if we have dynamic resolution, cannot be resolved to any file statically
                if not re.search(r'\$[0-9]', target):
                    # static resolution, good, we now extract the file
                    self.accessible.append(target.split("?")[0].lstrip("/"))
                
    def directoryIndexRule(self,line):
        parts=line.split()
        if len(parts)>1:
            self.dirIndex=parts[1].strip()
    
    def redirectMatchRule(self,line):
        # we only take the 403 case into account
        parts= line.split()
        if len(parts)>2:
            if parts[1].strip() == "403":
                self.blocked.append(parts[2].strip())

    def parse(self):
        try:
            f= open(self.filepath)
            for line in f.readlines():
                line=line.strip()
                rule=line.split(maxsplit=1)[0] if line else ""
                if not line or line.startswith("#") or rule not in self.rulesParser:
                    continue # skip this line
                # call the parsing function needed
                self.rulesParser[rule](line)
            self.accessible=[self.rewriteBase+p for p in self.accessible]
            return True
        except OSError as e:
            print(f"An error occurend while trying to open file '{self.filepath}'")
            return False
                
'''
This class receives the output from the Parser and checks for every file in the codebase if it is accessible
If directserving is used, only the blocked routes are checked
Otherwise, accessible is checked
'''
class CodeBaseChecker:
    def __init__(self,path,directServing):
        self.path=path
        self.directServing= directServing
    
    def __private_getallFiles(self):
        filenames=[]
        if os.path.isdir(self.path):
            for subdir,_,files in os.walk(self.path, followlinks=False):
                for file in files:
                    filepath= os.path.relpath(os.path.join(subdir,file), start=self.path)
                    filenames.append(filepath)
            return filenames
        else:
            print(f"There is no directory '{self.path}'")
            return None
     
    def check(self,accessiblePaths,blockedPaths,dirIndex):
        output=[]
        compiledPatterns=[re.compile(p) for p in blockedPaths]
        files= self.__private_getallFiles()
        if files is None:
            return None
        for file in files:
            file=file.strip()
            
            toCheck=[file]
            if dirIndex and Path(file).name==dirIndex:
                # we have to check if the directory is accessible too
                toCheck.append(str(Path(file).parent))
            
            # First we check if directServing is enabled
            if self.directServing:
                blocked=True
                # We check only blocked
                for entry in toCheck:
                    ok=True
                    for pattern in compiledPatterns:
                        if pattern.search(entry):
                            # it is blocked
                            ok=False
                            break
                    if ok:
                        blocked=False
                        break
                if not blocked:
                    for entry in toCheck:
                        output.append(entry)
            else:
                # it is not direct serving
                # we check accessiblePaths
                accessible=False
                for entry in toCheck:
                    ok=False
                    for p in accessiblePaths:
                        if p.lstrip("/")==entry.lstrip("/"):
                            ok=True
                            break
                    if ok:
                        accessible=True
                        break
                if accessible:
                    for entry in toCheck:
                        output.append(entry)
        cwd=os.getcwd()
        output = [os.path.join(cwd, f) for f in output]
        return output
          

argsParser = argparse.ArgumentParser(description="Parse .htaccess routing file and detect accessible files")
# Required arguments
argsParser.add_argument("htaccess_path", help="Path to the .htaccess file")
argsParser.add_argument("src_dir", help="Source directory (e.g., codebase root)")

# Optional args
argsParser.add_argument("--direct-serving", action="store_true", help="Enable directory serving analysis (DirectoryIndex)")
argsParser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")

args = argsParser.parse_args()

parser= Parser(args.htaccess_path)
if not parser.parse():
    print(f"An error ocurred during parsing.")
    sys.exit(1)
    
directserving= args.direct_serving
checker= CodeBaseChecker(args.src_dir,directserving)
foundFiles= checker.check(parser.accessible,parser.blocked,parser.dirIndex)
if foundFiles is None:
    print(f"An error ocurred during codebase checking.")
    sys.exit(1)

formatter= Formatter()
ok,output=formatter.format(args.format,foundFiles)
if ok:
    print(output)
    sys.exit(0)
sys.exit(1)