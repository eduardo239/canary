import * as vscode from 'vscode';
import { Finding, Severity, SEVERITY_ORDER, Vulnerability } from './types';

type Node = PackageNode | VulnNode;

class PackageNode extends vscode.TreeItem {
  constructor(readonly finding: Finding, readonly maxSeverity: Severity) {
    const d = finding.dependency;
    super(`${d.name}@${d.version}`, vscode.TreeItemCollapsibleState.Collapsed);
    const n = finding.vulnerabilities.length;
    const where = vscode.workspace.asRelativePath(d.location.file);
    this.description = `${n} vulnerabilidade${n > 1 ? 's' : ''} · ${d.direct ? 'direta' : 'transitiva'} · ${where}`;
    this.iconPath = severityIcon(maxSeverity);
    this.tooltip = new vscode.MarkdownString(
      `**${d.name}@${d.version}** (${d.ecosystem})\n\n` +
        `Declarado como \`${d.spec}\` em \`${where}\`` +
        (d.approximate ? '\n\n_Versão estimada a partir da faixa (sem lockfile)._' : ''),
    );
    this.contextValue = 'extScan.package';
    this.command = {
      command: 'vscode.open',
      title: 'Abrir',
      arguments: [
        vscode.Uri.file(d.location.file),
        { selection: new vscode.Range(d.location.line, d.location.startCol, d.location.line, d.location.endCol) },
      ],
    };
  }
}

class VulnNode extends vscode.TreeItem {
  constructor(readonly vuln: Vulnerability) {
    super(vuln.id, vscode.TreeItemCollapsibleState.None);
    this.description = `${vuln.severity} · ${vuln.summary}`;
    this.iconPath = severityIcon(vuln.severity);
    this.tooltip = new vscode.MarkdownString(
      `**${vuln.id}** — ${vuln.severity}\n\n${vuln.summary}\n\n` +
        (vuln.aliases.length ? `Aliases: ${vuln.aliases.join(', ')}\n\n` : '') +
        (vuln.fixedVersion ? `Corrigido em **${vuln.fixedVersion}**` : 'Sem versão corrigida conhecida'),
    );
    this.contextValue = 'extScan.vulnerability';
    this.command = { command: 'extScan.openAdvisory', title: 'Abrir advisory', arguments: [vuln.url] };
  }
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<Node> {
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private findings: Finding[] = [];

  update(findings: Finding[]): void {
    this.findings = findings;
    this.emitter.fire(undefined);
  }

  getTreeItem(node: Node): vscode.TreeItem {
    return node;
  }

  getChildren(node?: Node): Node[] {
    if (!node) {
      return this.findings
        .map((f) => new PackageNode(f, maxSeverity(f.vulnerabilities)))
        .sort(
          (a, b) =>
            SEVERITY_ORDER[b.maxSeverity] - SEVERITY_ORDER[a.maxSeverity] ||
            Number(b.finding.dependency.direct) - Number(a.finding.dependency.direct) ||
            String(a.label).localeCompare(String(b.label)),
        );
    }
    if (node instanceof PackageNode) {
      return node.finding.vulnerabilities.map((v) => new VulnNode(v));
    }
    return [];
  }
}

export function maxSeverity(vulns: Vulnerability[]): Severity {
  return vulns.reduce<Severity>((m, v) => (SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[m] ? v.severity : m), 'UNKNOWN');
}

function severityIcon(s: Severity): vscode.ThemeIcon {
  switch (s) {
    case 'CRITICAL':
    case 'HIGH':
      return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
    case 'MODERATE':
      return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
    default:
      return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
  }
}

