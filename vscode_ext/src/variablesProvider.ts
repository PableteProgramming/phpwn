import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface PhpwnVariable {
    name: string;
    type: 'safe' | 'input' | 'unknown';
}

export class VariableNode extends vscode.TreeItem {
    constructor(
        public readonly variable: PhpwnVariable,
        public readonly varsFilePath: string
    ) {
        super(variable.name, vscode.TreeItemCollapsibleState.None);

        this.description = variable.type;
        this.contextValue = `phpwnVar_${variable.type}`;

        switch (variable.type) {
            case 'safe':
                this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'));
                break;
            case 'input':
                this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconFailed'));
                break;
            case 'unknown':
                this.iconPath = new vscode.ThemeIcon('question', new vscode.ThemeColor('testing.iconQueued'));
                break;
        }
    }
}

export class VariablesProvider implements vscode.TreeDataProvider<VariableNode> {

    private _onDidChangeTreeData = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private varsFilePath: string | null = null;

    refresh(varsFilePath: string): void {
        this.varsFilePath = varsFilePath;
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: VariableNode): vscode.TreeItem {
        return element;
    }

    getChildren(): VariableNode[] {
        if (!this.varsFilePath || !fs.existsSync(this.varsFilePath)) {
            return [];
        }

        try {
            const content: PhpwnVariable[] = JSON.parse(fs.readFileSync(this.varsFilePath, 'utf-8'));
            return content.map(v => new VariableNode(v, this.varsFilePath!));
        } catch {
            return [];
        }
    }

    setVariableType(node: VariableNode, type: 'safe' | 'input' | 'unknown'): void {
        if (!this.varsFilePath || !fs.existsSync(this.varsFilePath)) {
            return;
        }
        try {
            const content: PhpwnVariable[] = JSON.parse(fs.readFileSync(this.varsFilePath, 'utf-8'));
            const idx = content.findIndex(v => v.name === node.variable.name);
            if (idx !== -1) {
                content[idx].type = type;
                fs.writeFileSync(this.varsFilePath, JSON.stringify(content, null, 2));
                this._onDidChangeTreeData.fire();
            }
        } catch (e) {
            vscode.window.showErrorMessage(`PHPwn: Failed to update variable type: ${e}`);
        }
    }
}