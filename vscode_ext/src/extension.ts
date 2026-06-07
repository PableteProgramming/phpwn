import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ReportProvider } from './reportProvider';
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

    // We register a TreeDataProvider for the report view, which will display the results of the analysis later on
    const reportProvider = new ReportProvider();
    vscode.window.registerTreeDataProvider('phpwnResults', reportProvider);

    // We register a command to run the analysis.
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.run', async () => {
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            await runPHPwn(context, workspaceRoot);
            reportProvider.refresh(workspaceRoot);
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
}

export function deactivate() {}