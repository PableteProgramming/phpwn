import shutil
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
    try:
        shutil.copytree("../Templates","Templates")
        shutil.copy("../PHPwn.py","PHPwn.py")
        shutil.copy("../setup.py","setup.py")
        shutil.copy("../run.py","run.py")
        shutil.copy("../wrapper.py","wrapper.py")
        shutil.copy("../requirements.txt","requirements.txt")
        shutil.copy("../Readme.md","Readme.md")
        createZip("PHPwn.zip")
        shutil.rmtree("Templates")
        os.remove("PHPwn.py")
        os.remove("setup.py")
        os.remove("run.py")
        os.remove("wrapper.py")
        os.remove("requirements.txt")
        os.remove("Readme.md")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"An error ocurred while releasing: {e}")

if __name__=="__main__":
    release()