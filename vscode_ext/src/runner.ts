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

function runCommand(cmd: string, cwd: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const proc = cp.exec(cmd, { cwd }, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(`${stderr}\n${stdout}`));
            } else {
                resolve();
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

function buildArgs(config: any, workspaceRoot: string): string {
    const target = path.resolve(workspaceRoot, config.target);
    const outputDir = path.resolve(workspaceRoot, config.outputDir);
    const varsFile = path.resolve(workspaceRoot, config.variablesFile);

    const args: string[] = [
        `"${target}"`,
        `"${outputDir}"`,
        `--output-json ${config.outputJson}`,
        `--output-csv ${config.outputCsv}`,
        `--vars-file "${varsFile}"`,
    ];

    if (config.excludes?.length) {
        args.push(`--excludes ${config.excludes.join(' ')}`);
    }
    if (config.directServing) {
        args.push('--direct-serving');
    }

    return args.join(' ');
}

export async function runPHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<'vars' | 'done'> {
    const configPath = path.join(workspaceRoot, 'phpwn.config.json');
    if (!fs.existsSync(configPath)) {
        throw new Error('phpwn.config.json not found in workspace root.');
    }
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'PHPwn',
        cancellable: false
    }, async (progress) => {
        progress.report({ message: 'Extracting PHPwn...' });
        await extractPHPwn(context, workspaceRoot);

        progress.report({ message: 'Setting up virtual environment...' });
        await setupVenv(workspaceRoot);

        progress.report({ message: 'Running analysis...' });
        const extractDir = getExtractDir(workspaceRoot);
        const python = getVenvPython(workspaceRoot);
        const args = buildArgs(config, workspaceRoot);

        const outputDir = path.resolve(workspaceRoot, config.outputDir);
        fs.mkdirSync(outputDir, { recursive: true });

        await runCommand(`"${python}" PHPwn.py ${args}`, extractDir);
    });

    const reportFile = path.resolve(workspaceRoot, config.outputDir, config.outputJson);
    if (fs.existsSync(reportFile)) {
        vscode.window.showInformationMessage('PHPwn: Analysis complete!');
        return 'done';
    }
    return 'vars';
}