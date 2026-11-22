import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import { describeError } from './net';
import { OsvClient } from './osv';
import { parseNpmProject } from './parsers/npm';
import { parsePnpmProject } from './parsers/pnpm';
import { parseYarnProject } from './parsers/yarn';
import { parseRequirements } from './parsers/python';
import { parseUvProject } from './parsers/uv';
import { recommendedVersion, renderReport, ReportFormat } from './report';
import { compileIgnorePatterns, isSafePyPackageName } from './security';
import { FindingsTreeProvider, maxSeverity } from './tree';
import { Dependency, Finding, Severity, SEVERITY_ORDER } from './types';

const MANIFEST_GLOB = '**/{package.json,package-lock.json,pnpm-lock.yaml,yarn.lock,requirements*.txt,pyproject.toml,uv.lock}';
const SOURCE = 'canary';

let diagnostics: vscode.DiagnosticCollection;
let tree: FindingsTreeProvider;
let treeView: vscode.TreeView<unknown>;
let status: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let osv: OsvClient;

/** Achados indexados por "arquivo|linha", usados pelo Quick Fix. */
const findingsByLine = new Map<string, Finding>();

/** Resultado da última verificação concluída (usado pelo relatório). */
let lastScan: { findings: Finding[]; dependencies: number; ignored: number; at: Date } | undefined;
/** Para notificar verificações automáticas só quando surgirem pacotes vulneráveis novos. */
let notifiedKeys = new Set<string>();

/** Novas tentativas automáticas quando uma verificação automática falha por rede. */
const AUTO_RETRY_DELAYS_MS = [15_000, 60_000, 180_000];
let autoRetryCount = 0;
let autoRetryTimer: NodeJS.Timeout | undefined;

let scanning = false;
let rescanRequested = false;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection(SOURCE);
  tree = new FindingsTreeProvider();
  treeView = vscode.window.createTreeView('canary.results', { treeDataProvider: tree, showCollapseAll: true });
  output = vscode.window.createOutputChannel('Canary');
  osv = new OsvClient((message) => output.appendLine(message));
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
    vscode.commands.registerCommand('canary.uvUpgrade', uvUpgrade),
    vscode.commands.registerCommand('canary.exportReport', exportReport),
    vscode.languages.registerCodeActionsProvider(
      [
        { pattern: '**/package.json' },
        { pattern: '**/package-lock.json' },
        { pattern: '**/pnpm-lock.yaml' },
        { pattern: '**/yarn.lock' },
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
  context.subscriptions.push(watcher, { dispose: () => (clearTimeout(timer), clearTimeout(autoRetryTimer)) });

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (['canary.ignorePackages', 'canary.includeDevDependencies', 'canary.exclude'].some((k) => e.affectsConfiguration(k))) {
        void runScan(false);
      }
    }),
  );

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
    const result = await vscode.window.withProgress(
      {
        location: manual ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window,
        title: 'Canary: verificando dependências',
        cancellable: manual,
      },
      async (progress, token) => {
        const abort = new AbortController();
        token.onCancellationRequested(() => abort.abort());

        progress.report({ message: 'procurando manifestos…' });
        const collected = await collectDependencies();
        // pacotes ignorados nunca são enviados à OSV.dev
        const isIgnored = compileIgnorePatterns(config().get<string[]>('ignorePackages', []));
        const deps = collected.filter((d) => !isIgnored(d));
        if (deps.length < collected.length) {
          output.appendLine(
            `[info] ${collected.length - deps.length} dependência(s) ignorada(s) por canary.ignorePackages (não enviadas à OSV.dev)`,
          );
        }
        if (token.isCancellationRequested) {
          return undefined;
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
        lastScan = { findings, dependencies: deps.length, ignored: collected.length - deps.length, at: new Date() };
        return { findings, total, dependencies: deps.length };
      },
    );
    if (result) {
      clearTimeout(autoRetryTimer);
      autoRetryCount = 0;
      status.command = 'canary.results.focus';
      notifyResult(result.findings, result.total, result.dependencies, manual);
    }
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      return;
    }
    const msg = describeError(err);
    output.appendLine(`[erro] verificação falhou: ${msg}`);
    // mantém os resultados anteriores (se houver) e indica o problema na barra de status
    setStatus('$(warning) Canary: sem conexão', `${msg}\n\nClique para verificar de novo.`);
    status.command = 'canary.scan';
    if (manual) {
      void vscode.window.showErrorMessage(`Canary: falha na verificação — ${msg}`, 'Tentar novamente', 'Ver log').then((choice) => {
        if (choice === 'Tentar novamente') {
          void runScan(true);
        } else if (choice === 'Ver log') {
          output.show(true);
        }
      });
    } else {
      scheduleAutoRetry();
    }
  } finally {
    scanning = false;
    if (rescanRequested) {
      rescanRequested = false;
      void runScan(false);
    }
  }
}

/** Verificação automática falhou: tenta de novo em silêncio, com intervalos crescentes. */
function scheduleAutoRetry(): void {
  clearTimeout(autoRetryTimer);
  const delay = AUTO_RETRY_DELAYS_MS[autoRetryCount];
  if (delay === undefined) {
    output.appendLine('[erro] novas tentativas automáticas esgotadas; use "Canary: Verificar vulnerabilidades".');
    return;
  }
  autoRetryCount++;
  output.appendLine(`[info] nova verificação automática em ${delay / 1000}s`);
  autoRetryTimer = setTimeout(() => void runScan(false), delay);
}

async function collectDependencies(): Promise<Dependency[]> {
  const exclude = config().get<string>('exclude') || undefined;
  const includeDev = config().get<boolean>('includeDevDependencies', true);
  const files = await vscode.workspace.findFiles(MANIFEST_GLOB, exclude);

  const npmDirs = new Set<string>();
  const npmLockDirs = new Set<string>();
  const pnpmLockDirs = new Set<string>();
  const yarnLockDirs = new Set<string>();
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
    } else if (base === 'yarn.lock') {
      yarnLockDirs.add(dir);
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

  // 1) projetos JS com lockfile (pnpm e yarn têm prioridade sobre o package-lock.json na mesma pasta)
  const jsLocked = await settle([
    ...[...pnpmLockDirs].map((d) => parsePnpmProject(d, { includeDev })),
    ...[...yarnLockDirs].filter((d) => !pnpmLockDirs.has(d)).map((d) => parseYarnProject(d, { includeDev })),
    ...[...npmLockDirs].filter((d) => !pnpmLockDirs.has(d) && !yarnLockDirs.has(d)).map((d) => parseNpmProject(d, { includeDev })),
  ]);
  // 2) package.json sem lockfile, ignorando membros de workspace já cobertos por um lockfile
  const members = new Set(jsLocked.flatMap((r) => r.members));
  const jsLoose = await settle(
    [...npmDirs]
      .filter((d) => !npmLockDirs.has(d) && !pnpmLockDirs.has(d) && !yarnLockDirs.has(d) && !members.has(d))
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
  void vscode.commands.executeCommand('setContext', 'canary.hasFindings', findings.length > 0);

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
  lastScan = undefined;
  notifiedKeys = new Set();
  void vscode.commands.executeCommand('setContext', 'canary.hasFindings', false);
  status.command = 'canary.results.focus';
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
  const target = recommendedVersion(finding);
  if (!target) {
    return undefined;
  }
  const unfixed = finding.vulnerabilities.filter((v) => !v.fixedVersion).length;

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
    (dep.manager === 'yarn' ? ' no package.json (depois rode "yarn install")' : '') +
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
  // roda um comando no terminal: só em pastas confiáveis e com nome de pacote válido
  if (!vscode.workspace.isTrusted || !isSafePyPackageName(dep.name)) {
    return undefined;
  }
  if (!finding.vulnerabilities.some((v) => v.fixedVersion)) {
    return undefined;
  }
  const action = new vscode.CodeAction(
    `Rodar "uv lock --upgrade-package ${dep.name}" no terminal`,
    vscode.CodeActionKind.QuickFix,
  );
  action.command = { command: 'canary.uvUpgrade', title: 'uv lock --upgrade-package', arguments: [dep.projectDir, dep.name] };
  action.diagnostics = [diag];
  action.isPreferred = !dep.versionLocation;
  return action;
}

/**
 * Executa "uv lock --upgrade-package <pacote>". Recebe só a pasta e o nome (nunca um comando pronto)
 * e revalida tudo, porque comandos podem ser chamados com argumentos arbitrários.
 */
function uvUpgrade(projectDir: unknown, packageName: unknown): void {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage('Canary: confie nesta pasta (Workspace Trust) para rodar comandos no terminal.');
    return;
  }
  if (typeof projectDir !== 'string' || typeof packageName !== 'string' || !isSafePyPackageName(packageName)) {
    void vscode.window.showErrorMessage('Canary: nome de pacote inválido; comando não executado.');
    return;
  }
  if (!vscode.workspace.getWorkspaceFolder(vscode.Uri.file(projectDir))) {
    void vscode.window.showErrorMessage('Canary: a pasta do projeto está fora do workspace; comando não executado.');
    return;
  }
  const terminal = vscode.window.createTerminal({ name: 'Canary', cwd: projectDir });
  terminal.show();
  terminal.sendText(`uv lock --upgrade-package ${packageName}`);
}

// ---------------------------------------------------------------------------
// Notificação e relatório
// ---------------------------------------------------------------------------

const ACTION_EXPORT = 'Exportar relatório';
const ACTION_RESCAN = 'Escanear novamente';
const ACTION_DETAILS = 'Ver detalhes';

/**
 * Verificação manual: sempre avisa. Automática (ao abrir ou ao mudar um lockfile): só avisa
 * quando aparece um pacote vulnerável que ainda não tinha sido notificado.
 */
function notifyResult(findings: Finding[], total: number, dependencies: number, manual: boolean): void {
  const keys = new Set(findings.map((f) => `${f.dependency.location.file}|${f.dependency.name}@${f.dependency.version}`));
  const hasNew = [...keys].some((k) => !notifiedKeys.has(k));
  notifiedKeys = keys;

  if (!findings.length) {
    if (manual) {
      void vscode.window
        .showInformationMessage(`Canary: nenhuma vulnerabilidade conhecida em ${dependencies} dependência(s).`, ACTION_RESCAN)
        .then(handleAction);
    }
    return;
  }
  if (!manual && !hasNew) {
    return;
  }
  const counts = findings
    .flatMap((f) => f.vulnerabilities)
    .reduce<Record<string, number>>((acc, v) => ((acc[v.severity] = (acc[v.severity] ?? 0) + 1), acc), {});
  const parts = (
    [
      ['CRITICAL', 'crítica'],
      ['HIGH', 'alta'],
      ['MODERATE', 'média'],
      ['LOW', 'baixa'],
    ] as [Severity, string][]
  )
    .filter(([s]) => counts[s])
    .map(([s, label]) => `${counts[s]} ${label}${counts[s] > 1 ? 's' : ''}`);
  const message =
    `Canary: ${findings.length} pacote(s) com ${total} vulnerabilidade(s)` + (parts.length ? ` — ${parts.join(', ')}.` : '.');

  const worstSeverity = findings.map((f) => maxSeverity(f.vulnerabilities)).reduce<Severity>(
    (m, s) => (SEVERITY_ORDER[s] > SEVERITY_ORDER[m] ? s : m),
    'UNKNOWN',
  );
  const shown =
    SEVERITY_ORDER[worstSeverity] >= SEVERITY_ORDER.HIGH
      ? vscode.window.showErrorMessage(message, ACTION_EXPORT, ACTION_RESCAN, ACTION_DETAILS)
      : vscode.window.showWarningMessage(message, ACTION_EXPORT, ACTION_RESCAN, ACTION_DETAILS);
  void shown.then(handleAction);
}

function handleAction(choice: string | undefined): void {
  if (choice === ACTION_EXPORT) {
    void exportReport();
  } else if (choice === ACTION_RESCAN) {
    void runScan(true);
  } else if (choice === ACTION_DETAILS) {
    void vscode.commands.executeCommand('canary.results.focus');
  }
}

const FORMATS: { format: ReportFormat; label: string; description: string; ext: string; filter: string }[] = [
  { format: 'markdown', label: '$(markdown) Markdown', description: 'Legível, bom para PRs, issues e documentação', ext: 'md', filter: 'Markdown' },
  { format: 'csv', label: '$(table) CSV', description: 'Para abrir no Excel, Google Sheets ou LibreOffice', ext: 'csv', filter: 'CSV' },
  { format: 'json', label: '$(json) JSON', description: 'Para integrar com outras ferramentas e CI', ext: 'json', filter: 'JSON' },
];

async function exportReport(): Promise<void> {
  if (!lastScan) {
    const choice = await vscode.window.showInformationMessage(
      'Canary: nenhuma verificação concluída ainda. Verificar agora?',
      ACTION_RESCAN,
    );
    if (choice === ACTION_RESCAN) {
      await runScan(true);
    }
    return;
  }
  const scan = lastScan;
  const picked = await vscode.window.showQuickPick(FORMATS, {
    title: 'Canary: exportar relatório de vulnerabilidades',
    placeHolder: 'Escolha o formato',
  });
  if (!picked) {
    return;
  }

  const folder = vscode.workspace.workspaceFolders?.[0];
  const stamp = scan.at.toISOString().slice(0, 10);
  const defaultUri = folder
    ? vscode.Uri.joinPath(folder.uri, `canary-report-${stamp}.${picked.ext}`)
    : vscode.Uri.file(path.join(os.homedir(), `canary-report-${stamp}.${picked.ext}`));
  const target = await vscode.window.showSaveDialog({
    defaultUri,
    filters: { [picked.filter]: [picked.ext] },
    saveLabel: 'Exportar',
    title: 'Salvar relatório do Canary',
  });
  if (!target) {
    return;
  }

  const content = renderReport(picked.format, scan.findings, {
    generatedAt: scan.at,
    workspace: vscode.workspace.name ?? (folder ? folder.name : 'workspace'),
    dependenciesScanned: scan.dependencies,
    ignored: scan.ignored,
    relativePath: (file) => vscode.workspace.asRelativePath(file),
  });
  try {
    await vscode.workspace.fs.writeFile(target, Buffer.from(content, 'utf8'));
  } catch (err: any) {
    void vscode.window.showErrorMessage(`Canary: não foi possível salvar o relatório — ${err?.message ?? err}`);
    return;
  }
  output.appendLine(`[info] relatório exportado: ${target.fsPath}`);

  const open = picked.format === 'markdown' ? 'Abrir prévia' : 'Abrir';
  const choice = await vscode.window.showInformationMessage(
    `Canary: relatório salvo em ${vscode.workspace.asRelativePath(target)}.`,
    open,
    'Mostrar na pasta',
  );
  if (choice === 'Abrir prévia') {
    await vscode.commands.executeCommand('markdown.showPreview', target);
  } else if (choice === 'Abrir') {
    await vscode.window.showTextDocument(target);
  } else if (choice === 'Mostrar na pasta') {
    await vscode.commands.executeCommand('revealFileInOS', target);
  }
}
