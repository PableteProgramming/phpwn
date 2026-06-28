'''
This script is the one that is going to configure everything before letting the analysis run.
This are the steps done by this script:
    1) If --vars passed:
        - Create necessary temporary dirs
        - Copy the source code to analyze into it
        - Copy preprocess.php into the directory
        - Call preprocess.php --list to list all the detected global vars
        - save it into phpwn.vars.json
    2) Else
        - Parse command line args for variables
        - Create necessary temporary dirs
        - Copy the source code to analyze into it
        - Copy all the Psalm stuff into the directory
            - Replace important parts like ingoreFiles entries, and psalm stubs and plugin files
            - Replace needed variables for preprocess.php (EXCLUDE_DIR,SAFE_PATTERNS,INPUT_PATTERS)
            - Install psalm
            - Run preprocess.php
        - Copy all the PHPStan stuff into it
            - Install PHPStan
            - Copy all the necessary files
            - Replace Exclude dirs to phpstan
            - Add the custom rules to phpstan.neon
            - Configure custom rules in composer.json
            - Fix namespaces into the rules
        - Copy codebaseChecker.py stuff
        - Copy report.py
'''
import argparse
import shutil
import os
from lxml import etree
import re
import subprocess
from pathlib import Path
import json
import sys

TEMPLATE_DIR="Templates"
PSALM_DIR="psalm"
PSALM_STUB_DIR="stubs"
PSALM_PLUGIN_DIR="plugins"
PHPSTAN_DIR="phpstan"
PHPSTAN_RULES_DIR="rules"

def addXml(filename,inTag,tag,values):
    if len(values)<=0:
        return True
    try:
        tree= etree.parse(filename)
    except OSError:
        print(f"[!] Could not open {filename}")
        return False
    except etree.XMLSyntaxError:
        print(f"[!] Could not parse {filename} — invalid XML")
        return False
        
    root= tree.getroot()
    foundTag= root.find(inTag)
    for v in values:
        entry= etree.SubElement(foundTag,tag)
        for key,value in v.items():
            entry.set(key,value)
    etree.indent(tree, space="\t")
    tree.write(filename,pretty_print=True, xml_declaration=True, encoding="UTF-8")
    return True

def parseArgs():
    parser = argparse.ArgumentParser(description="The PHPwn setup script.")
    # Required positional argument
    parser.add_argument("src_dir", help="The source directory to analyze.")
    parser.add_argument("out_dir", help="The output directory.")
    # Optional flags
    parser.add_argument("--excludes", "-e", nargs="+", default=[], help="Directories to skip.")
    parser.add_argument("--safe-patterns", "-s", nargs="+", default=[], help="Patterns for safe variables.")
    parser.add_argument("--xss-patterns", "-x", nargs="+", default=[], help="Patterns for xss variables.")
    parser.add_argument("--sql-patterns", "-l", nargs="+", default=[], help="Patterns for sql variables.")
    parser.add_argument("--vars","-v",action="store_true",help="Pass this variable to get a list of global variables.")
    parser.add_argument("--vars-file","-f",type=str,default="phpwn.vars.json", help="The path of the file with the variables.")
    parser.add_argument("--accessible-files","-a",action="store_true",help="Pass this if you want PHPwn to check for accessbile files based on an .htaccess routing file.")
    args= parser.parse_args()
    return args.src_dir,args.out_dir,args.excludes,args.safe_patterns,args.xss_patterns,args.sql_patterns,args.vars,args.vars_file,args.accessible_files

def buildPhpArray(elements):
    return ", ".join(f"'{elem}'" for elem in elements)

def appendToPhpFile(filename,var,value):
    try:
        f = open(filename,"r")
        content= f.read()
        f.close()
        content= re.sub(rf'\${var}\s*=\s*.*?;',f'${var} = {value}',content)
        f = open(filename,"w")
        f.write(content)
        f.close()
    except Exception as e:
        print(f"An error ocurred while trying to open {filename}: {e}")
        return False
    return True
        
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

def replaceInFile(filename,pattern,replacement):
    try:
        f= open(filename,"r")
        content= f.read()
        f.close()
        content= content.replace(pattern,replacement)
        f= open(filename,"w")
        f.write(content)
        f.close()
        return True
    except Exception as e:
        print(f"An error ocurred while opening {filename}: {e}")
        return False

def updateComposer(filename,namespace,dir):
    try:
        f= open(filename,"r")
        content= json.load(f)
        f.close()
        if "autoload-dev" not in content:
            content["autoload-dev"]={}
        if "psr-4" not in content["autoload-dev"]:
            content["autoload-dev"]["psr-4"]={}
        content["autoload-dev"]["psr-4"][namespace]= dir
        f= open(filename,"w")
        json.dump(content,f,indent=4)
        f.write("\n")
        f.close()
        return True
    except Exception as e:
        print(f"An error ocurred while opening and parsing {filename}: {e}")
        return False
        
def setup():
    srcDir, outDir, excludes, safePatterns, xssPatterns,sqlPatterns, vars,varsFile, accessibleFiles = parseArgs()
    
    excludes.extend(["preprocess.php",PSALM_DIR,PHPSTAN_DIR])
    currentDir=os.path.dirname(os.path.abspath(__file__))
    
    # we first copy the source dir into the temp dir
    print(f"[+] Creating {outDir} and copying source code")
    try:
        shutil.rmtree(outDir)
    except FileNotFoundError as e:
        pass
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        return False
    
    srcBaseName= os.path.basename(os.path.normpath(srcDir))
    srcPath= os.path.join(outDir,srcBaseName)
    shutil.copytree(srcDir,srcPath)
    
    psalmDir= os.path.join(srcPath,PSALM_DIR)
    psalmStubsDir=os.path.join(psalmDir,PSALM_STUB_DIR)
    psalmPluginsDir=os.path.join(psalmDir,PSALM_PLUGIN_DIR)
    psalmTemplatesDir= os.path.join(currentDir,TEMPLATE_DIR,"Psalm")
    os.mkdir(psalmDir)
    os.mkdir(psalmStubsDir)
    os.mkdir(psalmPluginsDir)
    
    if(vars):
        # we are in the first step, we just want to list the variables.
        # We copy preprocess.php
        shutil.copy(os.path.join(psalmTemplatesDir,"preprocess.php"),srcPath)
        if appendToPhpFile(os.path.join(srcPath,"preprocess.php"),"skipDirs",f"[{buildPhpArray(excludes)}];"):
            print(f"[+] Excludes where appended to preprocess.php")
        else:
            print(f"[!] An error occurred while trying to append excludes to preprocess.php")
            return False
        print("[+] Installing Psalm")
        if not runCommandOrFail(["composer", "require", "--dev","vimeo/psalm"],srcPath):
            return False
        print("[+] Running preprocess.php --list")
        ok,output=runCommandOrFail(["php", "preprocess.php", "--list"],srcPath,output=True)
        if not ok:
            return False
        try:
            f= open(varsFile,"w")
            # in case some error get's printed but the json still there
            obj_pos= output.find('{')
            arr_pos= output.find('[')
            if obj_pos== -1 and arr_pos== -1:
                print(f"An error ocurred while writing output of preprocess.php to {varsFile}: no JSON found")
                return False
            if obj_pos== -1:
                start= arr_pos
            elif arr_pos== -1:
                start= obj_pos
            else:
                start = min(obj_pos, arr_pos)
            output = output[start:]
            json.dump(json.loads(output),f,indent=2)
            f.close()
        except Exception as e:
            print(f"An error ocurred while writing output of preprocess.php to {varsFile}: {e}")
            return False
        shutil.rmtree(outDir)
        return True
    
    print(f"[+] Copying all Psalm important setup files")
    # Copy Psalm stuff now
    shutil.copy(os.path.join(psalmTemplatesDir,"psalm.xml"),os.path.join(srcPath,"psalm.xml"))
    shutil.copy(os.path.join(psalmTemplatesDir,"defs.php"),psalmStubsDir)
    shutil.copy(os.path.join(psalmTemplatesDir,"globalVarTainter.php"),psalmPluginsDir)
    shutil.copy(os.path.join(psalmTemplatesDir,"preprocess.php"),srcPath)
    
    # Applying exclude dirs to psalm.xml
    entries=[]
    for filename in excludes:
        entries.append({"name":filename})
        
    excludesFiles=[f for f in entries if Path(os.path.join(srcPath,f["name"])).is_file()]
    excludesDirs=[f for f in entries if f not in excludesFiles]
        
    if addXml(os.path.join(srcPath,"psalm.xml"),"projectFiles/ignoreFiles","file",excludesFiles):
        print(f"[+] Excludes files where appended to psalm.xml")
    else:
        print(f"[!] An error occurred while trying to append excludes files to psalm.xml")
        return False
    
    if addXml(os.path.join(srcPath,"psalm.xml"),"projectFiles/ignoreFiles","directory",excludesDirs):
        print(f"[+] Excludes dirs where appended to psalm.xml")
    else:
        print(f"[!] An error occurred while trying to append excludes dirs to psalm.xml")
        return False
    
    if addXml(os.path.join(srcPath,"psalm.xml"),"stubs","file",[{"name":os.path.join(PSALM_DIR,PSALM_STUB_DIR,"defs.php")}]):
        print(f"[+] Stubs where appended to psalm.xml")
    else:
        print(f"[!] An error occurred while trying to append stubs to psalm.xml")
        return False
    
    if addXml(os.path.join(srcPath,"psalm.xml"),"plugins","plugin",[{"filename":os.path.join(PSALM_DIR,PSALM_PLUGIN_DIR,"globalVarTainter.php")}]):
        print(f"[+] Plugins where appended to psalm.xml")
    else:
        print(f"[!] An error occurred while trying to append plugins to psalm.xml")
        return False
    
    if appendToPhpFile(os.path.join(srcPath,"preprocess.php"),"skipDirs",f"[{buildPhpArray(excludes)}];"):
        print(f"[+] Excludes where appended to preprocess.php")
    else:
        print(f"[!] An error occurred while trying to append excludes to preprocess.php")
        return False
    
    if appendToPhpFile(os.path.join(srcPath,"preprocess.php"),"safePatterns",f"[{buildPhpArray(safePatterns)}];"):
        print(f"[+] Safe patterns where appended to preprocess.php")
    else:
        print(f"[!] An error occurred while trying to append safe patterns to preprocess.php")
        return False
    
    if appendToPhpFile(os.path.join(srcPath,"preprocess.php"),"xssPatterns",f"[{buildPhpArray(xssPatterns)}];"):
        print(f"[+] Input patterns where appended to preprocess.php")
    else:
        print(f"[!] An error occurred while trying to append xss patterns to preprocess.php")
        return False
    
    if appendToPhpFile(os.path.join(srcPath,"preprocess.php"),"sqlPatterns",f"[{buildPhpArray(sqlPatterns)}];"):
        print(f"[+] Input patterns where appended to preprocess.php")
    else:
        print(f"[!] An error occurred while trying to append sql patterns to preprocess.php")
        return False
    
    if appendToPhpFile(os.path.join(srcPath,"preprocess.php"),"psalmPluginsDir",f'"{os.path.join(PSALM_DIR,PSALM_PLUGIN_DIR,"globalVarTainter.php")}";'):
        print(f"[+] psalm variable where appended to preprocess.php")
    else:
        print(f"[!] An error occurred while trying to append psalm variable to preprocess.php")
        return False
    
    print("[+] Installing Psalm")
    if not runCommandOrFail(["composer", "require", "--dev","vimeo/psalm"],srcPath):
        return False
    
    print("[+] Running preprocess.php")
    if not runCommandOrFail(["php", "preprocess.php"],srcPath):
        return False
    
    # now copying all necessary PHPStan 
    print("[+] Copying all necessary PHPStan setup files")
    phptanDir=os.path.join(srcPath,PHPSTAN_DIR)
    phpstanRulesDir= os.path.join(phptanDir,PHPSTAN_RULES_DIR)
    os.mkdir(phptanDir)
    os.mkdir(phpstanRulesDir)
    for file in Path(os.path.join(currentDir,TEMPLATE_DIR,"PHPStan")).glob("*.php"):
        shutil.copy(file, os.path.join(phpstanRulesDir,file.name))
        
    shutil.copy(os.path.join(currentDir,TEMPLATE_DIR,"PHPStan","phpstan.neon"),os.path.join(srcPath,"phpstan.neon"))
    
    print("[+] Applying excludes and custom Rules to phpstan.neon")
    excludesBlock="\n".join([f"        - {d}" for d in excludes])
    if replaceInFile(os.path.join(srcPath,"phpstan.neon"),"# EXCLUDE_PLACEHOLDER",excludesBlock):
        print("[+] excludes replaced successfully")
    else:
        print("[!] An error ocurred while writing excludes to phpstan.neon")
        return False
        
    if replaceInFile(os.path.join(srcPath,"phpstan.neon"),"# SCANDIR_PLACEHOLDER",f"        - {os.path.join(PHPSTAN_DIR,PHPSTAN_RULES_DIR)}"):
        print("[+] scanDir replaced successfully")
    else:
        print("[!] An error ocurred while writing scanDir to phpstan.neon")
        return False
        
    base= re.sub(r'[^a-zA-Z0-9]','',srcBaseName.rstrip("/\\"))
    namespace= (base[0].upper() + base[1:] if base else base) + "\\PHPStan\\"
    rulesBlock="\n".join([f"    - {namespace}{PHPSTAN_RULES_DIR}\\{Path(f).stem}" for f in Path(phpstanRulesDir).iterdir() if f.is_file()])
    if replaceInFile(os.path.join(srcPath,"phpstan.neon"),"# RULES_PLACEHOLDER",rulesBlock):
        print("[+] rules replaced successfully")
    else:
        print("[!] An error append while writing rules to phpstan.neon")
        return False
        
    if updateComposer(os.path.join(srcPath,"composer.json"),namespace,PHPSTAN_DIR+"/"):
        print("[+] composer.json got updated")
    else:
        print("[!] An error ocurred while updating composer.json")
        return False
        
    print("[+] Running dump-autoload")
    if not runCommandOrFail(["composer", "dump-autoload"],srcPath):
        return False
    
    # Now, fixing the namespaces in the .php rules
    for f in Path(phpstanRulesDir).iterdir():
        if f.is_file():
            if replaceInFile(os.path.join(phpstanRulesDir,os.path.basename(os.path.normpath(f))),"namespace $NAMESPACE;",f"namespace {namespace}{PHPSTAN_RULES_DIR};"):
                print(f"[+] namespace replaced successfully in {f}")
            else:
                print("[!] An error append while replacing namespaces in the rules")
                return False 
            
    print("[+] Installing PHPStan")
    if not runCommandOrFail(["composer", "require", "--dev","phpstan/phpstan"],srcPath):
        return False
    
    if accessibleFiles:
        shutil.copy(os.path.join(currentDir,TEMPLATE_DIR,"CodebaseCheck","codebaseCheck.py"),os.path.join(srcPath,"codebaseCheck.py"))
    shutil.copy(os.path.join(currentDir,TEMPLATE_DIR,"Report","report.py"),os.path.join(outDir,"report.py"))
    return True
    
if __name__=="__main__":
    if not setup():
        print(f"[!] An error ocurred during setup")
        sys.exit(1)
    else:
        print("[+] Setup done !")
        sys.exit(0)