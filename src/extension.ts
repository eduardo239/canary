import * as path from 'path';
import * as vscode from 'vscode';
import { OsvClient } from './osv';
import { parseNpmProject } from './parsers/npm';
import { parsePnpmProject } from './parsers/pnpm';
import { parseRequirements } from './parsers/python';
import { parseUvProject } from './parsers/uv';
import { FindingsTreeProvider, maxSeverity } from './tree';
import { Dependency, Finding, Severity, SEVERITY_ORDER } from './types';
import { compareVersions } from './version';

const MANIFEST_GLOB = '**/{package.json,package-lock.json,pnpm-lock.yaml,requirements*.txt,pyproject.toml,uv.lock}';
const SOURCE = 'canary';

let diagnostics: vscode.DiagnosticCollection;
let tree: FindingsTreeProvider;
let treeView: vscode.TreeView<unknown>;
let status: vscode.StatusBarItem;
let output: vscode.OutputChannel;
const osv = new OsvClient();

/** Achados indexados por "arquivo|linha", usados pelo Quick Fix. */
const findingsByLine = new Map<string, Finding>();

let scanning = false;
let rescanRequested = false;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection(SOURCE);
  tree = new FindingsTreeProvider();
  treeView = vscode.window.createTreeView('canary.results', { treeDataProvider: tree, showCollapseAll: true });
  output = vscode.window.createOutputChannel('Canary');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'canary.results.focus';
  setStatus('$(shield) Canary', 'Clique para ver as vulnerabilidades');
  status.show();

  context.subscriptions.push(
    diagnostics,
    output,
    status,
    treeView,
    vscode.commands.registerCommand('canary.scan', () => runScan(true)),
    vscode.commands.registerCommand('canary.clear', clearResults),
    vscode.commands.registerCommand('canary.openAdvisory', (url: string) => vscode.env.openExternal(vscode.Uri.parse(url))),
    vscode.commands.registerCommand('canary.runInTerminal', runInTerminal),
    vscode.languages.registerCodeActionsProvider(
      [
        { pattern: '**/package.json' },
        { pattern: '**/package-lock.json' },
        { pattern: '**/pnpm-lock.yaml' },
        { pattern: '**/requirements*.txt' },
        { pattern: '**/pyproject.toml' },
        { pattern: '**/uv.lock' },
      ],
      new UpgradeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );

  // re-scan quando manifestos mudam (salvar no editor, npm install, pip freeze...)
  const watcher = vscode.workspace.createFileSystemWatcher(MANIFEST_GLOB);
  let timer: NodeJS.Timeout | undefined;
  const onChange = (uri: vscode.Uri) => {
    if (!config().get<boolean>('scanOnChange', true) || /[\\/](node_modules|\.venv|venv)[\\/]/.test(uri.fsPath)) {
      return;
    }
    clearTimeout(timer);
    timer = setTimeout(() => runScan(false), 1500);
  };
  watcher.onDidChange(onChange);
  watcher.onDidCreate(onChange);
  watcher.onDidDelete(onChange);
  context.subscriptions.push(watcher, { dispose: () => clearTimeout(timer) });

  if (config().get<boolean>('scanOnStartup', true)) {
    void runScan(false);
  }
}

export function deactivate(): void {}

function config() {
  return vscode.workspace.getConfiguration('canary');
}

async function runScan(manual: boolean): Promise<void> {
  if (scanning) {
    rescanRequested = true;
    return;
  }
  scanning = true;
  try {
    await vscode.window.withProgress(
      {
        location: manual ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window,
        title: 'Canary: verificando dependências',
        cancellable: manual,
      },
      async (progress, token) => {
        const abort = new AbortController();
        token.onCancellationRequested(() => abort.abort());

        progress.report({ message: 'procurando manifestos…' });
        const deps = await collectDependencies();
        if (token.isCancellationRequested) {
          return;
        }
        progress.report({ message: `consultando OSV.dev (${deps.length} pacotes)…` });
        const start = Date.now();
        const findings = await osv.scan(deps, abort.signal);
        publish(findings);

        const total = findings.reduce((n, f) => n + f.vulnerabilities.length, 0);
        output.appendLine(
          `[${new Date().toLocaleTimeString()}] ${deps.length} dependências analisadas, ` +
            `${findings.length} pacotes vulneráveis, ${total} vulnerabilidades (${Date.now() - start} ms)`,
        );
        if (manual) {
          void vscode.window.showInformationMessage(
            findings.length
              ? `Canary: ${total} vulnerabilidade(s) em ${findings.length} pacote(s).`
              : `Canary: nenhuma vulnerabilidade conhecida em ${deps.length} dependência(s).`,
          );
        }
      },
    );
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      return;
    }
    const msg = err?.message ?? String(err);
    output.appendLine(`[erro] ${msg}`);
    setStatus('$(shield) Canary: erro', msg);
    if (manual) {
      void vscode.window.showErrorMessage(`Canary: falha na verificação — ${msg}`);
    }
  } finally {
    scanning = false;
    if (rescanRequested) {
      rescanRequested = false;
      void runScan(false);
    }
  }
}

async function collectDependencies(): Promise<Dependency[]> {
  const exclude = config().get<string>('exclude') || undefined;
  const includeDev = config().get<boolean>('includeDevDependencies', true);
  const files = await vscode.workspace.findFiles(MANIFEST_GLOB, exclude);

  const npmDirs = new Set<string>();
  const npmLockDirs = new Set<string>();
  const pnpmLockDirs = new Set<string>();
  const reqFiles: string[] = [];
  const pyprojectDirs = new Set<string>();
  const uvLockDirs = new Set<string>();
  for (const f of files) {
    const base = path.basename(f.fsPath);
    const dir = path.dirname(f.fsPath);
    if (base === 'package.json') {
      npmDirs.add(dir);
    } else if (base === 'package-lock.json') {
      npmLockDirs.add(dir);
    } else if (base === 'pnpm-lock.yaml') {
      pnpmLockDirs.add(dir);
    } else if (base === 'pyproject.toml') {
      pyprojectDirs.add(dir);
    } else if (base === 'uv.lock') {
      uvLockDirs.add(dir);
    } else {
      reqFiles.push(f.fsPath);
    }
  }

  const failures: unknown[] = [];
  const settle = async <T>(promises: Promise<T>[]): Promise<T[]> => {
    const results = await Promise.allSettled(promises);
    return results.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : (failures.push(r.reason), [])));
  };

  // 1) projetos JS com lockfile (pnpm tem prioridade se houver os dois)
  const jsLocked = await settle([
    ...[...pnpmLockDirs].map((d) => parsePnpmProject(d, { includeDev })),
    ...[...npmLockDirs].filter((d) => !pnpmLockDirs.has(d)).map((d) => parseNpmProject(d, { includeDev })),
  ]);
  // 2) package.json sem lockfile, ignorando membros de workspace já cobertos por um lockfile
  const members = new Set(jsLocked.flatMap((r) => r.members));
  const jsLoose = await settle(
    [...npmDirs]
      .filter((d) => !npmLockDirs.has(d) && !pnpmLockDirs.has(d) && !members.has(d))
      .map((d) => parseNpmProject(d, { includeDev })),
  );

  // membros de um workspace uv já estão no uv.lock da raiz: não analisar de novo
  const coveredByLock = (dir: string) =>
    [...uvLockDirs].some((lockDir) => lockDir !== dir && (dir + path.sep).startsWith(lockDir + path.sep));
  const uvDirs = new Set([...uvLockDirs, ...[...pyprojectDirs].filter((d) => !uvLockDirs.has(d) && !coveredByLock(d))]);
  const python = await settle([
    ...[...uvDirs].map((d) => parseUvProject(d, { includeDev })),
    ...reqFiles.map((f) => parseRequirements(f)),
  ]);

  for (const reason of failures) {
    output.appendLine(`[aviso] não foi possível ler um manifesto: ${reason}`);
  }
  return [...[...jsLocked, ...jsLoose].flatMap((r) => r.dependencies), ...python.flat()];
}

function publish(findings: Finding[]): void {
  diagnostics.clear();
  findingsByLine.clear();

  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const d = f.dependency;
    findingsByLine.set(`${d.location.file}|${d.location.line}`, f);
    const range = new vscode.Range(d.location.line, d.location.startCol, d.location.line, d.location.endCol);
    const list = byFile.get(d.location.file) ?? [];
    for (const v of f.vulnerabilities) {
      const fix = v.fixedVersion ? ` Corrigido em ${v.fixedVersion}.` : ' Sem versão corrigida conhecida.';
      const approx = d.approximate ? ` (versão estimada a partir de "${d.spec}")` : '';
      const via = d.direct ? '' : ' [transitiva]';
      const diag = new vscode.Diagnostic(
        range,
        `${d.name}@${d.version}${approx}${via}: ${v.summary} [${v.severity}].${fix}`,
        toDiagnosticSeverity(v.severity),
      );
      diag.source = SOURCE;
      diag.code = { value: v.id, target: vscode.Uri.parse(v.url) };
      list.push(diag);
    }
    byFile.set(d.location.file, list);
  }
  for (const [file, list] of byFile) {
    diagnostics.set(vscode.Uri.file(file), list);
  }

  tree.update(findings);
  updateBadge(findings);

  const total = findings.reduce((n, f) => n + f.vulnerabilities.length, 0);
  if (!total) {
    setStatus('$(shield) 0 vulnerabilidades', 'Nenhuma vulnerabilidade conhecida encontrada');
    status.backgroundColor = undefined;
    return;
  }
  const worst = findings.map((f) => maxSeverity(f.vulnerabilities)).reduce<Severity>(
    (m, s) => (SEVERITY_ORDER[s] > SEVERITY_ORDER[m] ? s : m),
    'UNKNOWN',
  );
  setStatus(`$(shield) ${total} vulnerabilidade${total > 1 ? 's' : ''}`, `Pior severidade: ${worst}. Clique para detalhes.`);
  status.backgroundColor = new vscode.ThemeColor(
    SEVERITY_ORDER[worst] >= SEVERITY_ORDER.HIGH ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground',
  );
}

function clearResults(): void {
  diagnostics.clear();
  findingsByLine.clear();
  tree.update([]);
  updateBadge([]);
  status.backgroundColor = undefined;
  setStatus('$(shield) Canary', 'Clique para ver as vulnerabilidades');
}

/**
 * Contador sobre o ícone do Canary na barra de atividades: quantidade de pacotes vulneráveis
 * (as mesmas entradas do painel). Sem valor, o VS Code esconde o contador.
 */
function updateBadge(findings: Finding[]): void {
  const packages = findings.length;
  if (!packages) {
    treeView.badge = undefined;
    return;
  }
  const vulns = findings.reduce((n, f) => n + f.vulnerabilities.length, 0);
  treeView.badge = {
    value: packages,
    tooltip:
      `${packages} pacote${packages > 1 ? 's' : ''} com vulnerabilidades ` +
      `(${vulns} vulnerabilidade${vulns > 1 ? 's' : ''} no total)`,
  };
}

function setStatus(text: string, tooltip: string): void {
  status.text = text;
  status.tooltip = tooltip;
}

function toDiagnosticSeverity(s: Severity): vscode.DiagnosticSeverity {
  if (s === 'CRITICAL' || s === 'HIGH') {
    return vscode.DiagnosticSeverity.Error;
  }
  if (s === 'MODERATE') {
    return vscode.DiagnosticSeverity.Warning;
  }
  return vscode.DiagnosticSeverity.Information;
}

/** Quick Fix: atualiza a versão para a menor que corrige todas as vulnerabilidades conhecidas do pacote. */
class UpgradeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const handled = new Set<number>();
    for (const diag of ctx.diagnostics) {
      if (diag.source !== SOURCE) {
        continue;
      }
      const line = diag.range.start.line;
      const finding = findingsByLine.get(`${doc.uri.fsPath}|${line}`);
      if (!finding) {
        continue;
      }
      if (!handled.has(line)) {
        handled.add(line);
        const upgrade = upgradeAction(doc, finding, diag);
        if (upgrade) {
          actions.push(upgrade);
        }
        const uv = uvLockAction(finding, diag);
        if (uv) {
          actions.push(uv);
        }
      }
      const id = typeof diag.code === 'object' ? String(diag.code.value) : undefined;
      const vuln = finding.vulnerabilities.find((v) => v.id === id);
      if (vuln) {
        const open = new vscode.CodeAction(`Abrir advisory ${vuln.id}`, vscode.CodeActionKind.QuickFix);
        open.command = { command: 'canary.openAdvisory', title: 'Abrir advisory', arguments: [vuln.url] };
        open.diagnostics = [diag];
        actions.push(open);
      }
    }
    return actions;
  }
}

function upgradeAction(doc: vscode.TextDocument, finding: Finding, diag: vscode.Diagnostic): vscode.CodeAction | undefined {
  const dep = finding.dependency;
  if (!dep.versionLocation) {
    return undefined; // transitiva: precisa atualizar quem a puxa (ou usar "overrides")
  }
  const fixes = finding.vulnerabilities.map((v) => v.fixedVersion).filter((v): v is string => !!v);
  if (!fixes.length) {
    return undefined;
  }
  const target = fixes.sort(compareVersions)[fixes.length - 1];
  const unfixed = finding.vulnerabilities.length - fixes.length;

  const loc = dep.versionLocation;
  const range = new vscode.Range(loc.line, loc.startCol, loc.line, loc.endCol);
  const current = doc.getText(range);
  let replacement = target;
  if (dep.ecosystem === 'npm') {
    const prefix = /^[\^~]|^>=\s*/.exec(current)?.[0] ?? '';
    replacement = prefix + target;
  }

  const title =
    `Atualizar ${dep.name} para ${replacement}` +
    (dep.manager === 'uv' ? ' no pyproject.toml (depois rode "uv lock")' : '') +
    (dep.manager === 'pnpm' ? ' no package.json (depois rode "pnpm install")' : '') +
    (dep.manager === 'npm' ? ' no package.json (depois rode "npm install")' : '') +
    (unfixed ? ` (${unfixed} vulnerabilidade(s) continuam sem correção)` : '');
  const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
  action.edit = new vscode.WorkspaceEdit();
  action.edit.replace(doc.uri, range, replacement);
  action.diagnostics = [diag];
  action.isPreferred = true;
  return action;
}

/**
 * uv: "uv lock --upgrade-package <nome>" funciona também para dependências transitivas,
 * desde que as restrições do pyproject.toml permitam a versão corrigida.
 */
function uvLockAction(finding: Finding, diag: vscode.Diagnostic): vscode.CodeAction | undefined {
  const dep = finding.dependency;
  if (dep.manager !== 'uv' || !dep.projectDir || dep.approximate) {
    return undefined;
  }
  if (!finding.vulnerabilities.some((v) => v.fixedVersion)) {
    return undefined;
  }
  const cmd = `uv lock --upgrade-package ${dep.name}`;
  const action = new vscode.CodeAction(`Rodar "${cmd}" no terminal`, vscode.CodeActionKind.QuickFix);
  action.command = { command: 'canary.runInTerminal', title: cmd, arguments: [dep.projectDir, cmd] };
  action.diagnostics = [diag];
  action.isPreferred = !dep.versionLocation;
  return action;
}

function runInTerminal(cwd: string, cmd: string): void {
  const terminal = vscode.window.createTerminal({ name: 'Canary', cwd });
  terminal.show();
  terminal.sendText(cmd);
}
