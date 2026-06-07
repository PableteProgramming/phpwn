import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// Shape of a single finding in report.json
interface Finding {
    type: string;
    file: string;
    line: number | string;
    snippet: string;
    source: string;
    variable: string;
    trace: { label: string; file: string; line: number }[];
}

// A node in the TreeView can be one of three things:
// - a group (e.g. "TaintedSql (12)")
// - a finding (e.g. "src/controllers/User.php:45")
// - a trace step (e.g. "$request → src/controllers/User.php:45")
type NodeKind = 'group' | 'finding' | 'trace';

export class ReportNode extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly kind: NodeKind,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly children: ReportNode[] = [],
        public readonly finding?: Finding
    ) {
        super(label, collapsibleState);

        if (kind === 'group') {
            this.iconPath = new vscode.ThemeIcon('warning');
        } else if (kind === 'finding') {
            this.iconPath = new vscode.ThemeIcon('bug');
            this.description = finding?.source ? `source: ${finding.source}` : '';
        } else if (kind === 'trace') {
            this.iconPath = new vscode.ThemeIcon('arrow-right');
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

    private loadReport(workspaceRoot: string): ReportNode[] {
        // Find report.json path from config
        const configPath = path.join(workspaceRoot, 'phpwn.config.json');
        if (!fs.existsSync(configPath)) {
            return [new ReportNode('No phpwn.config.json found', 'group', vscode.TreeItemCollapsibleState.None)];
        }

        const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        const reportPath = path.join(workspaceRoot, config.outputDir, config.outputJson);

        if (!fs.existsSync(reportPath)) {
            return [new ReportNode('No report.json found — run PHPwn first', 'group', vscode.TreeItemCollapsibleState.None)];
        }

        const findings: Finding[] = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

        // Group findings by type
        const grouped = new Map<string, Finding[]>();
        for (const f of findings) {
            if (!grouped.has(f.type)) {
                grouped.set(f.type, []);
            }
            grouped.get(f.type)!.push(f);
        }

        // Build tree nodes
        const groupNodes: ReportNode[] = [];
        for (const [type, items] of grouped) {
            const findingNodes = items.map(f => {
                const label = f.line ? `${f.file}:${f.line}` : f.file;

                // Trace children
                const traceNodes = f.trace.map(t =>
                    new ReportNode(
                        `${t.label} — ${t.file}:${t.line}`,
                        'trace',
                        vscode.TreeItemCollapsibleState.None
                    )
                );

                return new ReportNode(
                    label,
                    'finding',
                    traceNodes.length > 0
                        ? vscode.TreeItemCollapsibleState.Collapsed
                        : vscode.TreeItemCollapsibleState.None,
                    traceNodes,
                    f
                );
            });

            groupNodes.push(new ReportNode(
                `${type} (${items.length})`,
                'group',
                vscode.TreeItemCollapsibleState.Collapsed,
                findingNodes
            ));
        }

        return groupNodes;
    }
}