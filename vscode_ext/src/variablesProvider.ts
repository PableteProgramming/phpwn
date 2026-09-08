// This is the part of the extension that handles the variables panel.
import * as vscode from 'vscode';
import * as fs from 'fs';

// possible taint states for a variable
export interface TaintState {
    xss: boolean | null;
    sql: boolean | null;
}

// The JSON file is a map of name => PhpwnVariable object
export type VarsFile = { [key: string]: PhpwnVariable };

// This is the tree item for a variable in the variables panel.
// children is for nested variables, e.g. arrays or objects.
export interface PhpwnVariable {
    name: string;
    taint: TaintState;
    children: VarsFile;
}


// This function returns a human-readable description of the taint state of a variable.
function taintDescription(taint: TaintState): string {
    if (taint.xss === null && taint.sql === null) { return 'unclassified'; }
    const parts: string[] = [];
    if (taint.xss) { parts.push('XSS'); }
    if (taint.sql) { parts.push('SQL'); }
    if (parts.length === 0) { return 'none'; }
    return parts.join(' + ');
}

// returns the right icon for a variable based on its taint state.
function taintIcon(taint: TaintState): vscode.ThemeIcon {
    if (taint.xss === null && taint.sql === null) {
        return new vscode.ThemeIcon('question', new vscode.ThemeColor('testing.iconQueued'));
    }
    if (!taint.xss && !taint.sql) {
        //safe
        return new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'));
    }
    if (taint.xss && !taint.sql) {
        //only xss
        return new vscode.ThemeIcon('code', new vscode.ThemeColor('testing.iconFailed'));
    }
    if (!taint.xss && taint.sql) {
        //only sql
        return new vscode.ThemeIcon('database', new vscode.ThemeColor('testing.iconFailed'));
    }
    //both
    return new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconFailed'));
}

// this is the class of a variable node in the tree view.
export class VariableNode extends vscode.TreeItem {
    constructor(
        public readonly variable: PhpwnVariable,
        public readonly varsFilePath: string,
    ) {
        // First we check if the variable has children. If it does, we set the collapsible state to Collapsed, otherwise to None.
        const hasChildren = Object.keys(variable.children).length > 0;
        super(
            variable.name,
            hasChildren
                ? vscode.TreeItemCollapsibleState.Collapsed
                : vscode.TreeItemCollapsibleState.None
        );

        this.description = taintDescription(variable.taint);
        this.iconPath = taintIcon(variable.taint);

        // contextValue drives which inline buttons appear in package.json (see line 88).
        // format: phpwnVar_xss{0|1|null}_sql{0|1|null}
        const x = variable.taint.xss === null ? 'null' : variable.taint.xss ? '1' : '0';
        const s = variable.taint.sql === null ? 'null' : variable.taint.sql ? '1' : '0';
        this.contextValue = `phpwnVar_xss${x}_sql${s}`;
    }
}

// this is the class that provides the data for the variables panel. 
// It reads the JSON file and creates VariableNode objects for each variable.
export class VariablesProvider implements vscode.TreeDataProvider<VariableNode> {

    // vscode need this variables with these names...whatever.
    private _onDidChangeTreeData = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private varsFilePath: string | null = null;

    // to refresh the panel/treeview
    refresh(varsFilePath: string): void {
        this.varsFilePath = varsFilePath;
        this._onDidChangeTreeData.fire();
    }

    // kind of casting the VariableNode to a TreeItem, needed for the TreeDataProvider interface.
    getTreeItem(element: VariableNode): vscode.TreeItem {
        return element;
    }

    // returns the children of a variable node.
    // If no node is provided, returns the top-level variables.
    getChildren(element?: VariableNode): VariableNode[] {
        if (!this.varsFilePath || !fs.existsSync(this.varsFilePath)) {
            // No items — the right viewsWelcome content (Configure vs Run Analysis,
            // package.json, gated on the phpwn.configured context key) renders instead.
            return [];
        }
        try {
            // we now parse the vars file and create VariableNode objects for each variable.
            const content: VarsFile = JSON.parse(fs.readFileSync(this.varsFilePath, 'utf-8'));

            if (!element) {
                // Root level => return top-level variables
                return Object.values(content).map(v => new VariableNode(v, this.varsFilePath!));
            } else {
                // Children of a parent node
                return Object.values(element.variable.children).map(
                    child => new VariableNode(child, this.varsFilePath!)
                );
            }
        } catch {
            return [];
        }
    }

    // Sets taint on a node, with parent-propagation logic:
    // If the node has a classified parent, the child inherits the parent's taint instead.
    // Otherwise, set the requested taint and propagate recursively to all children.
    setTaint(node: VariableNode, xss: boolean | null, sql: boolean | null): void {
        if (!this.varsFilePath || !fs.existsSync(this.varsFilePath)) { return; }
        try {
            const content: VarsFile = JSON.parse(fs.readFileSync(this.varsFilePath, 'utf-8'));
            this._applyTaint(content, node.variable.name, xss, sql);
            // we only do one write at the end, not after each recursive call, to avoid unnecessary file writes.
            // that is why we need _applyTaint.
            fs.writeFileSync(this.varsFilePath, JSON.stringify(content, null, 2));
            this._onDidChangeTreeData.fire();
        } catch (e) {
            vscode.window.showErrorMessage(`PHPwn: Failed to update taint: ${e}`);
        }
    }

    // Recursive helper that changes `content` in place.
    // Separated so we can call it recursively for children without re-reading/re-writing the file.
    private _applyTaint(content: VarsFile, name: string, xss: boolean | null, sql: boolean | null): void {
        const target = this.findNode(content, name);
        if (!target) { return; }

        const parent = this.findParentNode(content, name, null);
        if (parent !== null && !(parent.taint.xss === null && parent.taint.sql === null)) {
            // Parent is classified => child must inherit, user can't override
            target.taint.xss = parent.taint.xss;
            target.taint.sql = parent.taint.sql;
            vscode.window.showInformationMessage(
                `PHPwn: "${parent.name}" is already classified — "${target.name}" inherits its taint.`
            );
        } else {
            target.taint.xss = xss;
            target.taint.sql = sql;
        }

        // Propagate recursively to all children
        for (const child of Object.values(target.children)) {
            this._applyTaintToNode(child, target.taint.xss, target.taint.sql);
        }
    }

    //Recursively force-sets taint on a node and all its descendants.
    // Used for child propagation (no parent-override check needed here).
    private _applyTaintToNode(node: PhpwnVariable, xss: boolean | null, sql: boolean | null): void {
        node.taint.xss = xss;
        node.taint.sql = sql;
        for (const child of Object.values(node.children)) {
            this._applyTaintToNode(child, xss, sql);
        }
    }

    // Finds a node anywhere in the tree by its name (dot-path).
    // Searches root level first, then children.
    private findNode(content: VarsFile, name: string): PhpwnVariable | null {
        for (const variable of Object.values(content)) {
            if (variable.name === name) { return variable; }
            const r = this.findNode(variable.children, name);
            if (r !== null) { return r; }
        }
        return null;
    }

    // Finds the parent node of a given node by its name (dot-path).
    // Searches root level first, then children.
    private findParentNode(content: VarsFile, name: string, parent: PhpwnVariable | null): PhpwnVariable | null {
        for (const variable of Object.values(content)) {
            if (variable.name === name) { return parent; }
            const r = this.findParentNode(variable.children, name, variable);
            if (r !== null) { return r; }
        }
        return null;
    }
}