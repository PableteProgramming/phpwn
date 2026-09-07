import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// ── New JSON format types ────────────────────────────────────────────────────

interface TraceEntry {
    label: string;
    file: string;
    line: number;
}

interface VulnNode {
    nodeType: 'vuln';
    name: string;
    snippet: string;
    line: number;
    trace: TraceEntry[];
}

interface FileNode {
    nodeType: 'file';
    name: string;
    children: VulnNode[];
}

interface VarNode {
    nodeType: 'var';
    name: string;
    children: FileNode[];
}

interface VulnTypeNode {
    nodeType: 'vulnType';
    name: string;
    // missingAccessControl: children are strings (file paths)
    // SQLI / XSS: children are VarNode[]
    children: string[] | VarNode[];
}

// ── Tree node ────────────────────────────────────────────────────────────────

type NodeKind = 'type' | 'source' | 'file' | 'line' | 'trace' | 'placeholder';

export class ReportNode extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly kind: NodeKind,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly children: ReportNode[] = [],
        public readonly command?: vscode.Command
    ) {
        super(label, collapsibleState);
        this.command = command;

        switch (kind) {
            case 'type':
                if (label.toLowerCase().includes('sql')) {
                    this.iconPath = new vscode.ThemeIcon('database', new vscode.ThemeColor('testing.iconFailed'));
                } else if (label.toLowerCase().includes('access')) {
                    this.iconPath = new vscode.ThemeIcon('file-code', new vscode.ThemeColor('testing.iconFailed'));
                } else {
                    this.iconPath = new vscode.ThemeIcon('code', new vscode.ThemeColor('testing.iconFailed'));
                }
                break;
            case 'source':
                this.iconPath = new vscode.ThemeIcon('variable', new vscode.ThemeColor('testing.iconPassed'));
                break;
            case 'file':
                this.iconPath = new vscode.ThemeIcon('file-text', new vscode.ThemeColor('notificationsInfoIcon.foreground'));
                break;
            case 'line':
                this.iconPath = new vscode.ThemeIcon('debug-breakpoint-log', new vscode.ThemeColor('list.warningForeground'));
                break;
            case 'trace':
                this.iconPath = new vscode.ThemeIcon('git-commit');
                break;
            case 'placeholder':
                this.iconPath = new vscode.ThemeIcon('info');
                break;
        }
    }
}

// ── Provider ─────────────────────────────────────────────────────────────────

export class ReportProvider implements vscode.TreeDataProvider<ReportNode> {

    private _onDidChangeTreeData = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private roots: ReportNode[] = [];

    refresh(workspaceRoot: string): void {
        this.roots = this.loadReport(workspaceRoot);
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: ReportNode): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ReportNode): ReportNode[] {
        if (!element) { return this.roots; }
        return element.children;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private makeOpenCommand(filePath: string, line?: number): vscode.Command {
        if (line !== undefined) {
            return {
                command: 'vscode.open',
                title: 'Open File',
                arguments: [
                    vscode.Uri.file(filePath),
                    {
                        selection: new vscode.Range(
                            new vscode.Position(Number(line) - 1, 0),
                            new vscode.Position(Number(line) - 1, 0)
                        )
                    }
                ]
            };
        }
        return {
            command: 'vscode.open',
            title: 'Open File',
            arguments: [vscode.Uri.file(filePath)]
        };
    }

    // ── report loader ─────────────────────────────────────────────────────────

    private loadReport(workspaceRoot: string): ReportNode[] {
        const configPath = path.join(workspaceRoot, 'phpwn.config.json');
        if (!fs.existsSync(configPath)) {
            return [new ReportNode('No phpwn.config.json found', 'placeholder', vscode.TreeItemCollapsibleState.None)];
        }

        try {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
            const reportPath = path.join(workspaceRoot, config.outputDir, config.outputJson);

            if (!fs.existsSync(reportPath)) {
                return [new ReportNode('Please run PHPwn first', 'placeholder', vscode.TreeItemCollapsibleState.None)];
            }

            const report: VulnTypeNode[] = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
            const srcDir = path.resolve(workspaceRoot, config.target);

            return report.map(vulnTypeNode => this.buildTypeNode(vulnTypeNode, srcDir));
        } catch (e) {
            return [new ReportNode(`Failed to load report: ${e}`, 'placeholder', vscode.TreeItemCollapsibleState.None)];
        }
    }

    // ── build type node (top level) ───────────────────────────────────────────

    private buildTypeNode(vulnTypeNode: VulnTypeNode, srcDir: string): ReportNode {
        const { name, children } = vulnTypeNode;

        // missingAccessControl: children are plain file-path strings
        if (name === 'missingAccessControl') {
            const fileNodes = (children as string[]).map(filePath => {
                const absPath = path.resolve(srcDir, filePath);
                return new ReportNode(
                    filePath,
                    'file',
                    vscode.TreeItemCollapsibleState.None,
                    [],
                    this.makeOpenCommand(absPath)
                );
            });
            return new ReportNode(
                `${name} (${fileNodes.length})`,
                'type',
                vscode.TreeItemCollapsibleState.Collapsed,
                fileNodes
            );
        }

        // SQLI / XSS: children are VarNode[]
        const varNodes = children as VarNode[];

        // Count total findings across all vars
        const totalFindings = varNodes.reduce(
            (sum, v) => sum + v.children.reduce((s, f) => s + f.children.length, 0),
            0
        );

        const sourceNodes = varNodes.map(varNode => this.buildVarNode(varNode, srcDir));

        return new ReportNode(
            `${name} (${totalFindings})`,
            'type',
            vscode.TreeItemCollapsibleState.Collapsed,
            sourceNodes
        );
    }

    // ── build var (source) node ───────────────────────────────────────────────

    private buildVarNode(varNode: VarNode, srcDir: string): ReportNode {
        const findingCount = varNode.children.reduce((s, f) => s + f.children.length, 0);
        const fileNodes = varNode.children.map(fileNode => this.buildFileNode(fileNode, srcDir));

        return new ReportNode(
            `${varNode.name} (${findingCount})`,
            'source',
            vscode.TreeItemCollapsibleState.Collapsed,
            fileNodes
        );
    }

    // ── build file node ───────────────────────────────────────────────────────

    private buildFileNode(fileNode: FileNode, srcDir: string): ReportNode {
        const absFile = path.resolve(srcDir, fileNode.name);
        const lineNodes = fileNode.children.map(vuln => this.buildVulnNode(vuln, absFile, srcDir));

        return new ReportNode(
            `${fileNode.name} (${fileNode.children.length})`,
            'file',
            vscode.TreeItemCollapsibleState.Collapsed,
            lineNodes,
            this.makeOpenCommand(absFile)
        );
    }

    // ── build vuln (line) node ────────────────────────────────────────────────

    private buildVulnNode(vuln: VulnNode, absFile: string, srcDir: string): ReportNode {
        const traceNodes = vuln.trace.map(t => {
            const absTrace = path.resolve(srcDir, t.file);
            return new ReportNode(
                `${t.label} — ${t.file}:${t.line}`,
                'trace',
                vscode.TreeItemCollapsibleState.None,
                [],
                this.makeOpenCommand(absTrace, t.line)
            );
        });

        const snippetPreview = vuln.snippet ? ' — ' + vuln.snippet.slice(0, 60) + '...' : '';

        return new ReportNode(
            `line ${vuln.line}${snippetPreview}`,
            'line',
            traceNodes.length > 0
                ? vscode.TreeItemCollapsibleState.Collapsed
                : vscode.TreeItemCollapsibleState.None,
            traceNodes,
            this.makeOpenCommand(absFile, vuln.line)
        );
    }
}