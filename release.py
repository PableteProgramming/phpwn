import zipfile
import os
import sys

def createZip(name):
    try:
        f=zipfile.ZipFile(name,"w",zipfile.ZIP_DEFLATED)
        f.write("ReleaseReadme.md", arcname="README.md")
        f.write("LICENSE")
        for file in ["PHPwn.py", "setup.py","run.py","wrapper.py","requirements.txt"]:
            f.write(file)
        for dirpath, _, files in os.walk("Templates"):
            for file in files:
                filepath= os.path.join(dirpath,file)
                f.write(filepath)
        f.close()
        return True
    except Exception as e:
        print(f"An error ocurred while trying to zip the files to {name}: {e}")
        return False

def release():
    return createZip("PHPwn.zip")

if __name__=="__main__":
    sys.exit(0 if release() else 1)
