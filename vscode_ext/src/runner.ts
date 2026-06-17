import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as cp from 'child_process';
import AdmZip from 'adm-zip';

// Where PHPwn gets extracted inside the workspace
const PHPWN_DIR = '.phpwn';

function getExtractDir(workspaceRoot: string): string {
    return path.join(workspaceRoot, PHPWN_DIR);
}

function getVenvPython(workspaceRoot: string): string {
    const base = getExtractDir(workspaceRoot);
    if (process.platform === 'win32') {
        return path.join(base, '.venv', 'Scripts', 'python.exe');
    }
    return path.join(base, '.venv', 'bin', 'python3');
}

function runCommand(cmd: string, cwd: string): Promise<number> {
    return new Promise((resolve, reject) => {
        const proc = cp.exec(cmd, { cwd }, (error, stdout, stderr) => {
            if (error && error.code === undefined) {
                // Truly failed to spawn (e.g. command not found)
                reject(new Error(`${stderr}\n${stdout}`));
            } else {
                resolve(error?.code ?? 0);
            }
        });
    });
}

async function extractPHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<void> {
    const extractDir = getExtractDir(workspaceRoot);
    const zipPath = path.join(context.extensionPath, 'resources', 'PHPwn.zip');

    if (!fs.existsSync(zipPath)) {
        throw new Error('PHPwn bundle not found in extension resources.');
    }

    // Always re-extract to make sure we have the latest version
    if (fs.existsSync(extractDir)) {
        fs.rmSync(extractDir, { recursive: true, force: true });
    }
    fs.mkdirSync(extractDir, { recursive: true });

    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractDir, true);
}

async function setupVenv(workspaceRoot: string): Promise<void> {
    const extractDir = getExtractDir(workspaceRoot);
    const venvDir = path.join(extractDir, '.venv');

    // Create venv only if it doesn't exist
    if (!fs.existsSync(venvDir)) {
        await runCommand('python3 -m venv .venv', extractDir);
    }

    // Always install requirements in case they changed
    const pip = process.platform === 'win32'
        ? path.join(venvDir, 'Scripts', 'pip.exe')
        : path.join(venvDir, 'bin', 'pip3');

    await runCommand(`"${pip}" install -r requirements.txt`, extractDir);
}

export async function configurePHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<void> {
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'PHPwn',
        cancellable: false
    }, async (progress) => {
        progress.report({ message: 'Extracting PHPwn...' });
        await extractPHPwn(context, workspaceRoot);

        progress.report({ message: 'Setting up virtual environment...' });
        await setupVenv(workspaceRoot);

        progress.report({ message: 'Configuring PHPwn...' });
        const extractDir = getExtractDir(workspaceRoot);
        const python = getVenvPython(workspaceRoot);

        console.log('extractDir: ' + extractDir);
        console.log('passed dir: ' + path.relative(extractDir, workspaceRoot));

        await runCommand(`"${python}" PHPwn.py --configure ${path.relative(extractDir, workspaceRoot)}`, extractDir);
    });
}

export async function runPHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<'vars' | 'done'> {
    const configPath = path.join(workspaceRoot, 'phpwn.config.json');
    if (!fs.existsSync(configPath)) {
        throw new Error('phpwn.config.json not found in workspace root.');
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
        const code = await runCommand(`"${python}" PHPwn.py ${path.relative(extractDir, workspaceRoot)}`, extractDir);
        if (code === 0) {
            vscode.window.showInformationMessage('PHPwn: Analysis complete!');
            result='done';
        }
        else if (code === 2) {
            // Code 2 means we need user input on variable categorization
            vscode.window.showInformationMessage('PHPwn: Variables analysis complete!');
            result='vars';
        }
        else {
            throw new Error(`PHPwn analysis failed with exit code ${code}.`);
        }
    });
    return result!;
}