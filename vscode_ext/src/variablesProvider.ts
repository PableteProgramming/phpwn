import * as vscode from 'vscode';
import * as fs from 'fs';

export interface TaintState {
    xss: boolean | null;
    sql: boolean | null;
}

export interface PhpwnVariable {
    name: string;
    taint: TaintState;
    children: { [key: string]: PhpwnVariable };
}

// The JSON root is a map of name => PhpwnVariable
export type VarsFile = { [key: string]: PhpwnVariable };

function taintDescription(taint: TaintState): string {
    if (taint.xss === null && taint.sql === null) { return 'unclassified'; }
    const parts: string[] = [];
    if (taint.xss) { parts.push('XSS'); }
    if (taint.sql) { parts.push('SQL'); }
    if (parts.length === 0) { return 'none'; }
    return parts.join(' + ');
}

function taintIcon(taint: TaintState): vscode.ThemeIcon {
    if (taint.xss === null && taint.sql === null) {
        return new vscode.ThemeIcon('question', new vscode.ThemeColor('testing.iconQueued'));
    }
    if (!taint.xss && !taint.sql) {
        return new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'));
    }
    if(taint.xss && !taint.sql) {
        return new vscode.ThemeIcon('code', new vscode.ThemeColor('testing.iconFailed'));
    }
    if(!taint.xss && taint.sql) {
        return new vscode.ThemeIcon('database', new vscode.ThemeColor('testing.iconFailed'));
    }
    return new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconFailed'));
}

export class VariableNode extends vscode.TreeItem {
    constructor(
        public readonly variable: PhpwnVariable,
        public readonly varsFilePath: string,
        public readonly isChild: boolean = false
    ) {
        const hasChildren = Object.keys(variable.children).length > 0;
        super(
            variable.name,
            hasChildren
                ? vscode.TreeItemCollapsibleState.Collapsed
                : vscode.TreeItemCollapsibleState.None
        );

        this.description = taintDescription(variable.taint);
        this.iconPath = taintIcon(variable.taint);

        // contextValue drives which inline buttons appear in package.json
        // format: phpwnVar_xss{0|1|null}_sql{0|1|null}
        const x = variable.taint.xss === null ? 'null' : variable.taint.xss ? '1' : '0';
        const s = variable.taint.sql === null ? 'null' : variable.taint.sql ? '1' : '0';
        this.contextValue = `phpwnVar_xss${x}_sql${s}`;
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

    getChildren(element?: VariableNode): VariableNode[] {
        if (!this.varsFilePath || !fs.existsSync(this.varsFilePath)) {
            return [new VariableNode(
                { name: 'Please run PHPwn first', taint: { xss: null, sql: null }, children: {} },
                ''
            )];
        }
        try {
            const content: VarsFile = JSON.parse(fs.readFileSync(this.varsFilePath, 'utf-8'));

            if (!element) {
                // Root level — return top-level variables
                return Object.values(content).map(v => new VariableNode(v, this.varsFilePath!));
            } else {
                // Children of a parent node
                return Object.values(element.variable.children).map(
                    child => new VariableNode(child, this.varsFilePath!, true)
                );
            }
        } catch {
            return [];
        }
    }

    /**
     * Sets xss and/or sql taint on a node.
     * If the node has children and they are still null, propagates to them.
     */
    setTaint(node: VariableNode, xss: boolean | null, sql: boolean | null): void {
        if (!this.varsFilePath || !fs.existsSync(this.varsFilePath)) { return; }
        try {
            const content: VarsFile = JSON.parse(fs.readFileSync(this.varsFilePath, 'utf-8'));

            // Find the node in the tree by name
            const target = this.findNode(content, node.variable.name);
            if (!target) { return; }

            target.taint.xss = xss;
            target.taint.sql = sql;

            // Propagate to children that are still unclassified (null)
            for (const child of Object.values(target.children)) {
                if (child.taint.xss === null) { child.taint.xss = xss; }
                if (child.taint.sql === null) { child.taint.sql = sql; }
            }

            fs.writeFileSync(this.varsFilePath, JSON.stringify(content, null, 2));
            this._onDidChangeTreeData.fire();
        } catch (e) {
            vscode.window.showErrorMessage(`PHPwn: Failed to update taint: ${e}`);
        }
    }

    /**
     * Finds a node anywhere in the tree by its name (dot-path).
     * Searches root level first, then children.
     */
    private findNode(content: VarsFile, name: string): PhpwnVariable | null {
        for (const variable of Object.values(content)) {
            if (variable.name === name) { return variable; }
            for (const child of Object.values(variable.children)) {
                if (child.name === name) { return child; }
            }
        }
        return null;
    }
}