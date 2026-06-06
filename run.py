'''
This script runs Psalm and PHPStan and analyzes their output to create a report
setup.py needs to be ran before !
This script does the following steps:
    - Run Psalm
    - Run PHPStan
    - Run the custom codebasechecker script
    - Copy report.py
    - Run report.py
'''