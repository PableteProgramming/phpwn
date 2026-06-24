import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ReportProvider } from './reportProvider';
import { VariablesProvider } from './variablesProvider';
import { runPHPwn, configurePHPwn } from './runner';

export function activate(context: vscode.ExtensionContext) {

    const workspaceRoot = vscode.workspace.workspaceFolders?.[0].uri.fsPath;

    function getConfigPath(): string | null {
        if (!workspaceRoot) { return null; }
        return path.join(workspaceRoot, 'phpwn.config.json');
    }

    function configExists(): boolean {
        const configPath = getConfigPath();
        return configPath !== null && fs.existsSync(configPath);
    }

    function getVarsFilePath(): string | null {
        if (!workspaceRoot) { return null; }
        const configPath = getConfigPath();
        if (!configPath || !fs.existsSync(configPath)) { return null; }
        const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        return path.resolve(workspaceRoot, config.variablesFile);
    }

    const reportProvider = new ReportProvider();
    vscode.window.registerTreeDataProvider('phpwnResults', reportProvider);

    const variablesProvider = new VariablesProvider();
    vscode.window.registerTreeDataProvider('phpwnVariables', variablesProvider);

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.run', async () => {
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            if (!configExists()) {
                vscode.window.showErrorMessage('PHPwn: Please run "PHPwn: Configure" first.');
                return;
            }
            try {
                const result = await runPHPwn(context, workspaceRoot);
                if (result === 'vars') {
                    const varsFile = getVarsFilePath();
                    if (varsFile) {
                        variablesProvider.refresh(varsFile);
                    }
                    vscode.window.showInformationMessage('PHPwn: Please categorize the variables in the PHPwn Variables panel, then run again.');
                } else {
                    reportProvider.refresh(workspaceRoot);
                }
            } catch (e) {
                vscode.window.showErrorMessage(`PHPwn: ${e}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.showReport', () => {
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            if (!configExists()) {
                vscode.window.showErrorMessage('PHPwn: Please run "PHPwn: Configure" first.');
                return;
            }
            reportProvider.refresh(workspaceRoot);
        })
    );

    // Taint classification commands — called from inline buttons in the variables panel
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markXSS', (node) => {
            variablesProvider.setTaint(node, true, false);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markSQL', (node) => {
            variablesProvider.setTaint(node, false, true);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markBoth', (node) => {
            variablesProvider.setTaint(node, true, true);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markNone', (node) => {
            variablesProvider.setTaint(node, false, false);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.refreshReport', () => {
            if (!workspaceRoot) { return; }
            reportProvider.refresh(workspaceRoot);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.refreshVariables', () => {
            const varsFile = getVarsFilePath();
            if (!varsFile) { return; }
            variablesProvider.refresh(varsFile);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.configure', () => {
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            const configPath = getConfigPath()!;
            const openConfig = () => {
                vscode.workspace.openTextDocument(configPath).then(doc => {
                    vscode.window.showTextDocument(doc);
                });
            };
            if (fs.existsSync(configPath)) {
                vscode.window.showInformationMessage('PHPwn: config file already exists.');
                openConfig();
            } else {
                configurePHPwn(context, workspaceRoot).then(() => {
                    vscode.window.showInformationMessage('PHPwn: Configuration complete! Please run "PHPwn: Run Analysis" to start.');
                    openConfig();
                }).catch(e => {
                    vscode.window.showErrorMessage(`PHPwn: Configuration failed: ${e}`);
                });
            }
        })
    );
}

export function deactivate() { }