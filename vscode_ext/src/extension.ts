import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ReportProvider } from './reportProvider';
import { VariablesProvider } from './variablesProvider';
import { runPHPwn, configurePHPwn } from './runner';

// This function is called when the extension is activated.
// It sets up the commands and tree data providers for the extension to use later on.

// the needed constants for the extension
export const CONFIG_FILE_NAME = 'phpwn.config.json';

export function activate(context: vscode.ExtensionContext) {
    // Read fresh on every call (not captured once here) so commands keep
    // working correctly if the workspace folder changes after activation.
    function getWorkspaceRoot(): string | undefined {
        return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    }

    // This function gives the absolute path to the config file if it exists, otherwise returns null
    function getConfigPath(): string | null {
        const workspaceRoot = getWorkspaceRoot();
        if (!workspaceRoot) { return null; }
        return path.join(workspaceRoot, CONFIG_FILE_NAME);
    }

    // This function checks if the config file exists in the workspace
    function configExists(): boolean {
        const configPath = getConfigPath();
        return configPath !== null && fs.existsSync(configPath);
    }

    // This function retrieves the path to the variables file specified in the config file
    function getVarsFilePath(): string | null {
        const workspaceRoot = getWorkspaceRoot();
        if (!workspaceRoot) { return null; }
        if(!configExists()) { return null; }
        const configPath = getConfigPath();
        if (!configPath) { return null; }
        try {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
            if (!config.variablesFile) {
                vscode.window.showErrorMessage('PHPwn: variablesFile not specified in config.');
                return null;
            }
            return path.resolve(workspaceRoot, config.variablesFile);
        } catch (e) {
            vscode.window.showErrorMessage(`PHPwn: Failed to read ${CONFIG_FILE_NAME}: ${e}`);
            return null;
        }
    }

    // Create instances of the ReportProvider and VariablesProvider classes, and register them with VS Code
    const reportProvider = new ReportProvider();
    vscode.window.registerTreeDataProvider('phpwnResults', reportProvider);
    const variablesProvider = new VariablesProvider();
    vscode.window.registerTreeDataProvider('phpwnVariables', variablesProvider);

    // Tracks whether phpwn.config.json exists, via a context key used by the
    // viewsWelcome content in package.json (when: !phpwn.configured / phpwn.configured)
    // to switch between the "Configure PHPwn" and "Run Analysis" buttons.
    function updateConfiguredContext(): void {
        vscode.commands.executeCommand('setContext', 'phpwn.configured', configExists());
    }
    updateConfiguredContext();
    context.subscriptions.push(
        vscode.workspace.onDidChangeWorkspaceFolders(() => updateConfiguredContext())
    );

    // the PHPwn run Command: this is the main command that runs the PHPwn analysis
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.run', async () => {
            const workspaceRoot = getWorkspaceRoot();
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            if (!configExists()) {
                // we need the config file to run the analysis, so if it doesn't exist, we show an error message
                vscode.window.showErrorMessage('PHPwn: Please run "PHPwn: Configure" first.');
                return;
            }
            try {
                // Now, we run the PHPwn analysis using the runPHPwn function defined in runner.ts.
                const result = await runPHPwn(context, workspaceRoot);
                // if the result is 'vars', it means that the analysis found variables that need to be categorized,
                // so we refresh the variables panel and show a message to the user.
                if (result === 'vars') {
                    const varsFile = getVarsFilePath();
                    if (varsFile) {
                        variablesProvider.refresh(varsFile);
                    }
                    vscode.window.showInformationMessage('PHPwn: Please categorize the variables in the PHPwn Variables panel, then run again.');
                } else {
                    // otherwise, the results are out ! We show them
                    reportProvider.refresh(workspaceRoot);
                }
            } catch (e) {
                vscode.window.showErrorMessage(`PHPwn: ${e}`);
            }
        })
    );

    // This is the command to show the report panel.
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.showReport', () => {
            const workspaceRoot = getWorkspaceRoot();
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

    // Taint classification commands
    // They are called from inline buttons in the variables panel
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

    // This is needed in case we want a parent to not overwrite it's child taint classification.
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.markUnclassified', (node) => {
            variablesProvider.setTaint(node, null, null);
        })
    );

    // This is the refresh button for the report panel
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.refreshReport', () => {
            const workspaceRoot = getWorkspaceRoot();
            if (!workspaceRoot) { return; }
            reportProvider.refresh(workspaceRoot);
        })
    );

    // Same but for the variables panel
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.refreshVariables', () => {
            const varsFile = getVarsFilePath();
            if (!varsFile) { return; }
            variablesProvider.refresh(varsFile);
        })
    );

    // this is the configure command, it creates the config file if not existing.
    context.subscriptions.push(
        vscode.commands.registerCommand('phpwn.configure', () => {
            const workspaceRoot = getWorkspaceRoot();
            if (!workspaceRoot) {
                vscode.window.showErrorMessage('PHPwn: No workspace folder open.');
                return;
            }
            const configPath = getConfigPath();
            if (!configPath) {
                vscode.window.showErrorMessage('PHPwn: Could not determine config file path.');
                return;
            }
            const openConfig = () => {
                vscode.workspace.openTextDocument(configPath).then(doc => {
                    vscode.window.showTextDocument(doc);
                });
            };
            // if already existing, we just open it, otherwise we create it and then open it. No overwriting.
            if (fs.existsSync(configPath)) {
                vscode.window.showInformationMessage('PHPwn: config file already exists.');
                openConfig();
                updateConfiguredContext();
            } else {
                // we call configurePHPwn to create the config file and set up the environment. This function is defined in runner.ts.
                configurePHPwn(context, workspaceRoot).then(() => {
                    vscode.window.showInformationMessage('PHPwn: Configuration complete! Please run "PHPwn: Run Analysis" to start.');
                    openConfig();
                    updateConfiguredContext();
                }).catch(e => {
                    vscode.window.showErrorMessage(`PHPwn: Configuration failed: ${e}`);
                });
            }
        })
    );
}

// the deactivate function does nothing.
export function deactivate() { }
