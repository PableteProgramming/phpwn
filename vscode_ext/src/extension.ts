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

    // Helper to get varsFile path from config
    function getVarsFilePath(): string | null {
        if (!workspaceRoot) { return null; }
        const configPath = getConfigPath();
        if (!configPath || !fs.existsSync(configPath)) { return null; }
        const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        return path.resolve(workspaceRoot, config.variablesFile);
    }

    // We register a TreeDataProvider for the report view, which will display the results of the analysis later on
    const reportProvider = new ReportProvider();
    vscode.window.registerTreeDataProvider('phpwnResults', reportProvider);

    // We register a TreeDataProvider for the variables view, which will display the variables for the user to categorize
    const variablesProvider = new VariablesProvider();
    vscode.window.registerTreeDataProvider('phpwnVariables', variablesProvider);

    // We register a command to run the analysis.
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

    // We register a command to show the report, which simply refreshes the TreeDataProvider to display the latest results.
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

    // Variable categorization commands — called from inline buttons in the variables panel
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markSafe', (node) => {
            variablesProvider.setVariableType(node, 'safe');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markInput', (node) => {
            variablesProvider.setVariableType(node, 'input');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markUnknown', (node) => {
            variablesProvider.setVariableType(node, 'unknown');
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

    // the command to configure PHPwn.
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.configure', () => {
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            const configPath = getConfigPath()!;
            if (fs.existsSync(configPath)) {
                vscode.window.showInformationMessage('PHPwn: config file already exists.');
            } else {
                configurePHPwn(context, workspaceRoot).then(() => {
                    vscode.window.showInformationMessage('PHPwn: Configuration complete! Please run "PHPwn: Run Analysis" to start.');
                }).catch(e => {
                    vscode.window.showErrorMessage(`PHPwn: Configuration failed: ${e}`);
                });
            }
            vscode.workspace.openTextDocument(configPath).then(doc => {
                vscode.window.showTextDocument(doc);
            });
        })
    );
}

export function deactivate() { }