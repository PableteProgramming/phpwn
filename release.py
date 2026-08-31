import zipfile
import os

def createZip(name):
    try:
        f=zipfile.ZipFile(name,"w",zipfile.ZIP_DEFLATED)
        for file in ["PHPwn.py", "setup.py","run.py","wrapper.py","requirements.txt", "Readme.md"]:
            f.write(file)
        for dirpath, _, files in os.walk("Templates"):
            for file in files:
                filepath= os.path.join(dirpath,file)
                f.write(filepath)
        f.close()
    except Exception as e:
        print(f"An error ocurred while trying to zip the files to {name}: {e}")

def release():
    createZip("PHPwn.zip")

if __name__=="__main__":
    release()