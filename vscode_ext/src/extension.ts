import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ReportProvider } from './reportProvider';
import { VariablesProvider } from './variablesProvider';
import { runPHPwn } from './runner';

export function activate(context: vscode.ExtensionContext) {

    // On activation, ensure config file exists in workspace root
    // If not there yet, we copy the template from the extension's resources
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0].uri.fsPath;
    if (workspaceRoot) {
        const configPath = path.join(workspaceRoot, 'phpwn.config.json');
        if (!fs.existsSync(configPath)) {
            const configTemplate = path.join(context.extensionPath, 'resources', 'phpwn.config.json');
            fs.copyFileSync(configTemplate, configPath);
            vscode.window.showInformationMessage('PHPwn: config file ' + configPath + ' created at workspace root. Please configure it before running.');
        }
    }

    // Helper to get varsFile path from config
    function getVarsFilePath(): string | null {
        if (!workspaceRoot) { return null; }
        const configPath = path.join(workspaceRoot, 'phpwn.config.json');
        if (!fs.existsSync(configPath)) { return null; }
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
            try {
                const result = await runPHPwn(context, workspaceRoot);
                if (result === 'vars') {
                    // First run: variables file was created, ask user to categorize
                    const varsFile = getVarsFilePath();
                    if (varsFile) {
                        variablesProvider.refresh(varsFile);
                    }
                    vscode.window.showInformationMessage('PHPwn: Please categorize the variables in the PHPwn Variables panel, then run again.');
                } else {
                    // Full run: show results
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
}

export function deactivate() {}