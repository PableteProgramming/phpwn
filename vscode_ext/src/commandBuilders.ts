// Pure, VS-Code-API-free helpers for building the shell commands runner.ts
// executes. Kept separate from runner.ts (which imports 'vscode') so they can
// be unit-tested with plain mocha/node, without the full vscode-test/Electron
// harness.

export function pythonExecutableName(platform: NodeJS.Platform = process.platform): string {
    return platform === 'win32' ? 'python' : 'python3';
}

export function buildVenvCommand(platform: NodeJS.Platform = process.platform): string {
    return `${pythonExecutableName(platform)} -m venv .venv`;
}

export function buildPipInstallCommand(pip: string): string {
    return `"${pip}" install -r requirements.txt`;
}

export function buildConfigureCommand(python: string, relativeWorkspacePath: string): string {
    return `"${python}" PHPwn.py --configure "${relativeWorkspacePath}"`;
}

export function buildRunCommand(python: string, relativeWorkspacePath: string): string {
    return `"${python}" PHPwn.py "${relativeWorkspacePath}"`;
}
