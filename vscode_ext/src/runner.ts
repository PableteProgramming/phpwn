// This is the part of the extension that handles the whole functioning of the extension.
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as cp from 'child_process';
import AdmZip from 'adm-zip';
import { CONFIG_FILE_NAME } from './extension';

// Where PHPwn gets extracted inside the workspace
const PHPWN_DIR = '.phpwn';
const RESOURCES_DIR = 'resources';
const ZIP_FILE = 'PHPwn.zip';

// this returns the absolute path to the extraction directory of PHPwn.
function getExtractDir(workspaceRoot: string): string {
    return path.join(workspaceRoot, PHPWN_DIR);
}

// this returns the absolute path to the python executable inside the virtual environment of PHPwn.
function getVenvPython(workspaceRoot: string): string {
    const base = getExtractDir(workspaceRoot);
    if (process.platform === 'win32') {
        return path.join(base, '.venv', 'Scripts', 'python.exe');
    }
    return path.join(base, '.venv', 'bin', 'python3');
}

// This function is a helper function that runs a command in a given working directory and returns a promise 
// that resolves with the exit code, stdout, and stderr of the command. 
// It is used to run PHPwn commands and handle their output.
function runCommand(cmd: string, cwd: string): Promise<{ code: number, stdout: string, stderr: string }> {
    return new Promise((resolve, reject) => {
        const proc = cp.exec(cmd, { cwd }, (error, stdout, stderr) => {
            if (error && error.code === undefined) {
                reject(new Error(`${stderr}\n${stdout}`));
            } else {
                resolve({
                    code: error?.code ?? 0,
                    stdout,
                    stderr
                });
            }
        });
    });
}

// this function extracts the PHPwn.zip file from the extension's resources to the workspace directory.
async function extractPHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<void> {
    const extractDir = getExtractDir(workspaceRoot);
    const zipPath = path.join(context.extensionPath, RESOURCES_DIR, ZIP_FILE);

    if (!fs.existsSync(zipPath)) {
        throw new Error('PHPwn.zip not found in extension resources.');
    }

    // Always re-extract to make sure we have the latest version
    if (fs.existsSync(extractDir)) {
        fs.rmSync(extractDir, { recursive: true, force: true });
    }
    fs.mkdirSync(extractDir, { recursive: true });

    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractDir, true);
}

// This function sets up a Python virtual environment in the extracted PHPwn directory 
// and installs the required dependencies for PHPwn to run.
async function setupVenv(workspaceRoot: string): Promise<void> {
    const extractDir = getExtractDir(workspaceRoot);
    const venvDir = path.join(extractDir, '.venv');
    // Create venv only if it doesn't exist
    if (!fs.existsSync(venvDir)) {
        const r = await runCommand('python3 -m venv .venv', extractDir);
        if (r.code !== 0) {
            throw new Error(`Failed to create the Python virtual environment: ${r.stderr || r.stdout}`);
        }
    }

    // Always install requirements in case they changed
    const pip = process.platform === 'win32'
        ? path.join(venvDir, 'Scripts', 'pip.exe')
        : path.join(venvDir, 'bin', 'pip3');

    const r = await runCommand(`"${pip}" install -r requirements.txt`, extractDir);
    if (r.code !== 0) {
        throw new Error(`Failed to install PHPwn's Python dependencies: ${r.stderr || r.stdout}`);
    }
}

// This function configures PHPwn by extracting it, setting up the virtual environment,
// and running the configuration command.
export async function configurePHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<void> {
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'PHPwn',
        cancellable: false
    }, async (progress) => {
        progress.report({ message: 'Extracting PHPwn...' });
        await extractPHPwn(context, workspaceRoot);

        progress.report({ message: 'Setting up virtual environment and dependencies...' });
        await setupVenv(workspaceRoot);

        progress.report({ message: 'Configuring PHPwn...' });
        const extractDir = getExtractDir(workspaceRoot);
        const python = getVenvPython(workspaceRoot);

        const r = await runCommand(`"${python}" PHPwn.py --configure ${path.relative(extractDir, workspaceRoot)}`, extractDir);
        if (r.code !== 0) {
            throw new Error(`PHPwn configuration failed: ${r.stderr || r.stdout}`);
        }
    });
}

// This function runs the PHPwn analysis
export async function runPHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<'vars' | 'done'> {
    const configPath = path.join(workspaceRoot, CONFIG_FILE_NAME);
    if (!fs.existsSync(configPath)) {
        throw new Error(`${CONFIG_FILE_NAME} not found in workspace root.`);
    }

    const extractDir = getExtractDir(workspaceRoot);
    const python = getVenvPython(workspaceRoot);
    if (!fs.existsSync(extractDir)) {
        throw new Error('PHPwn is not configured. Please run "PHPwn: Configure" first.');
    }
    if (!fs.existsSync(python)) {
        throw new Error('PHPwn virtual environment is not set up. Please run "PHPwn: Configure" first.');
    }
    let result: 'vars' | 'done' | undefined;

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'PHPwn',
        cancellable: false
    }, async (progress) => {
        progress.report({ message: 'Running analysis...' });

        // we run the PHPwn internal script.
        const r = await runCommand(`"${python}" PHPwn.py ${path.relative(extractDir, workspaceRoot)}`, extractDir);
        if (r.code === 0) {
            vscode.window.showInformationMessage('PHPwn: Analysis complete!');
            result = 'done';
        }
        else if (r.code === 2) {
            // Code 2 means we need user input on variable categorization
            vscode.window.showInformationMessage('PHPwn: Variables analysis complete!');
            result = 'vars';
        }
        else {
            throw new Error(`PHPwn analysis failed with exit code ${r.code}: ${r.stderr || r.stdout}`);
        }
    });
    return result!;
}