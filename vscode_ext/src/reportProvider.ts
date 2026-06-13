import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

interface Finding {
    type: string;
    file: string;
    line: number | string;
    snippet: string;
    source: string;
    variable: string;
    trace: { label: string; file: string; line: number }[];
}

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
                }
                else if (label.toLowerCase().includes('access')) {
                    this.iconPath = new vscode.ThemeIcon('file-code', new vscode.ThemeColor('testing.iconFailed'));
                }
                else {
                    this.iconPath = new vscode.ThemeIcon('code', new vscode.ThemeColor('testing.iconFailed'));
                }
                break;
            case 'source':
                this.iconPath = new vscode.ThemeIcon('variable',new vscode.ThemeColor('testing.iconPassed'));
                break;
            case 'file':
                this.iconPath = new vscode.ThemeIcon('file-text',new vscode.ThemeColor('notificationsInfoIcon.foreground'));
                break;
            case 'line':
                this.iconPath = new vscode.ThemeIcon('debug-breakpoint-log',new vscode.ThemeColor('list.warningForeground'));
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
        if (!element) {
            return this.roots;
        }
        return element.children;
    }

    private makeOpenCommand(filePath: string, line?: number): vscode.Command {
        if (line) {
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

    private loadReport(workspaceRoot: string): ReportNode[] {
        const configPath = path.join(workspaceRoot, 'phpwn.config.json');
        if (!fs.existsSync(configPath)) {
            return [new ReportNode('No phpwn.config.json found', 'placeholder', vscode.TreeItemCollapsibleState.None)];
        }

        const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        const reportPath = path.join(workspaceRoot, config.outputDir, config.outputJson);

        if (!fs.existsSync(reportPath)) {
            return [new ReportNode('Please run PHPwn first', 'placeholder', vscode.TreeItemCollapsibleState.None)];
        }

        const findings: Finding[] = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
        const srcDir = path.resolve(workspaceRoot, config.target);

        // Group by type
        const byType = new Map<string, Finding[]>();
        for (const f of findings) {
            if (!byType.has(f.type)) { byType.set(f.type, []); }
            byType.get(f.type)!.push(f);
        }

        const typeNodes: ReportNode[] = [];

        for (const [type, items] of byType) {

            // missingAccessControl — special case: type → file only
            if (type === 'missingAccessControl') {
                const fileNodes = items.map(f => {
                    const absPath = path.resolve(srcDir, f.file);
                    return new ReportNode(
                        f.file,
                        'file',
                        vscode.TreeItemCollapsibleState.None,
                        [],
                        this.makeOpenCommand(absPath)
                    );
                });
                typeNodes.push(new ReportNode(
                    `${type} (${items.length})`,
                    'type',
                    vscode.TreeItemCollapsibleState.Collapsed,
                    fileNodes
                ));
                continue;
            }

            // SQLI and XSS — type → source → file → line
            const bySource = new Map<string, Finding[]>();
            for (const f of items) {
                const src = f.source || 'unknown';
                if (!bySource.has(src)) { bySource.set(src, []); }
                bySource.get(src)!.push(f);
            }

            const sourceNodes: ReportNode[] = [];

            for (const [source, sourceItems] of bySource) {

                // Group by file
                const byFile = new Map<string, Finding[]>();
                for (const f of sourceItems) {
                    if (!byFile.has(f.file)) { byFile.set(f.file, []); }
                    byFile.get(f.file)!.push(f);
                }

                const fileNodes: ReportNode[] = [];

                for (const [file, fileItems] of byFile) {
                    const absFile = path.resolve(srcDir, file);

                    const lineNodes: ReportNode[] = fileItems.map(f => {
                        // Trace children
                        const traceNodes = f.trace.map(t => {
                            const absTrace = path.resolve(srcDir, t.file);
                            return new ReportNode(
                                `${t.label} — ${t.file}:${t.line}`,
                                'trace',
                                vscode.TreeItemCollapsibleState.None,
                                [],
                                this.makeOpenCommand(absTrace, t.line)
                            );
                        });

                        return new ReportNode(
                            `line ${f.line}${f.snippet ? ' — ' + f.snippet.slice(0, 60) + '...' : ''}`,
                            'line',
                            traceNodes.length > 0
                                ? vscode.TreeItemCollapsibleState.Collapsed
                                : vscode.TreeItemCollapsibleState.None,
                            traceNodes,
                            this.makeOpenCommand(absFile, Number(f.line))
                        );
                    });

                    fileNodes.push(new ReportNode(
                        `${file} (${fileItems.length})`,
                        'file',
                        vscode.TreeItemCollapsibleState.Collapsed,
                        lineNodes,
                        this.makeOpenCommand(absFile)
                    ));
                }

                sourceNodes.push(new ReportNode(
                    `${source} (${sourceItems.length})`,
                    'source',
                    vscode.TreeItemCollapsibleState.Collapsed,
                    fileNodes
                ));
            }

            typeNodes.push(new ReportNode(
                `${type} (${items.length})`,
                'type',
                vscode.TreeItemCollapsibleState.Collapsed,
                sourceNodes
            ));
        }

        return typeNodes;
    }
}