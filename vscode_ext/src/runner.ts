// This is the part of the extension that handles the whole functioning of the extension.
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as cp from 'child_process';
import AdmZip from 'adm-zip';
import { CONFIG_FILE_NAME } from './extension';
import { buildVenvCommand, buildPipInstallCommand, buildConfigureCommand, buildRunCommand } from './commandBuilders';

// Where PHPwn gets extracted inside the workspace
const PHPWN_DIR = '.phpwn';
const RESOURCES_DIR = 'resources';
const ZIP_FILE = 'PHPwn.zip';
// Version of the bundled PHPwn.zip (written into the extension's own
// resources at packaging time) and the marker left behind in a workspace's
// .phpwn/ recording which version was last extracted there.
const VERSION_FILE = 'PHPWN_VERSION.txt';
const VERSION_MARKER_FILE = '.phpwn-version';

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

// Reads the PHPwn version bundled with the currently installed extension.
// Falls back to 'unknown' if the marker file isn't present (e.g. a build
// packaged before this feature existed), so ensureUpToDate still behaves
// safely - it just means a one-time re-extraction the first time it runs.
function getBundledVersion(context: vscode.ExtensionContext): string {
    const versionPath = path.join(context.extensionPath, RESOURCES_DIR, VERSION_FILE);
    if (!fs.existsSync(versionPath)) {
        return 'unknown';
    }
    return fs.readFileSync(versionPath, 'utf-8').trim();
}

// Reads the version marker left in the workspace from the last extraction, if any.
function getInstalledVersion(workspaceRoot: string): string | null {
    const markerPath = path.join(getExtractDir(workspaceRoot), VERSION_MARKER_FILE);
    if (!fs.existsSync(markerPath)) {
        return null;
    }
    return fs.readFileSync(markerPath, 'utf-8').trim();
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
        const r = await runCommand(buildVenvCommand(), extractDir);
        if (r.code !== 0) {
            throw new Error(`Failed to create the Python virtual environment: ${r.stderr || r.stdout}`);
        }
    }

    // Always install requirements in case they changed
    const pip = process.platform === 'win32'
        ? path.join(venvDir, 'Scripts', 'pip.exe')
        : path.join(venvDir, 'bin', 'pip3');

    const r = await runCommand(buildPipInstallCommand(pip), extractDir);
    if (r.code !== 0) {
        throw new Error(`Failed to install PHPwn's Python dependencies: ${r.stderr || r.stdout}`);
    }
}

// Makes sure the PHPwn copy extracted into this workspace's .phpwn/ matches
// the version bundled with the currently installed extension, re-extracting
// and reinstalling dependencies if it's missing or out of date. This is what
// lets upgrading the extension actually take effect on already-configured
// projects, instead of silently keeping whatever was extracted the first
// time "PHPwn: Configure" ran.
async function ensureUpToDate(context: vscode.ExtensionContext, workspaceRoot: string): Promise<void> {
    const bundledVersion = getBundledVersion(context);
    const installedVersion = getInstalledVersion(workspaceRoot);
    const extractDir = getExtractDir(workspaceRoot);

    if (fs.existsSync(extractDir) && installedVersion === bundledVersion) {
        return;
    }

    await extractPHPwn(context, workspaceRoot);
    await setupVenv(workspaceRoot);
    fs.writeFileSync(path.join(extractDir, VERSION_MARKER_FILE), bundledVersion);
}

// This function configures PHPwn by making sure it's extracted and set up,
// and running the configuration command.
export async function configurePHPwn(context: vscode.ExtensionContext, workspaceRoot: string): Promise<void> {
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'PHPwn',
        cancellable: false
    }, async (progress) => {
        progress.report({ message: 'Setting up PHPwn...' });
        await ensureUpToDate(context, workspaceRoot);

        progress.report({ message: 'Configuring PHPwn...' });
        const extractDir = getExtractDir(workspaceRoot);
        const python = getVenvPython(workspaceRoot);

        const r = await runCommand(buildConfigureCommand(python, path.relative(extractDir, workspaceRoot)), extractDir);
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

    let result: 'vars' | 'done' | undefined;

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'PHPwn',
        cancellable: false
    }, async (progress) => {
        progress.report({ message: 'Checking PHPwn installation...' });
        await ensureUpToDate(context, workspaceRoot);

        progress.report({ message: 'Running analysis...' });
        const extractDir = getExtractDir(workspaceRoot);
        const python = getVenvPython(workspaceRoot);

        // we run the PHPwn internal script.
        const r = await runCommand(buildRunCommand(python, path.relative(extractDir, workspaceRoot)), extractDir);
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
