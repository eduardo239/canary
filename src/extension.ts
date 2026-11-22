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

/** Findings indexed by "file|line", used by the Quick Fix. */
const findingsByLine = new Map<string, Finding>();

/** Result of the last completed scan (used by the report). */
let lastScan: { findings: Finding[]; dependencies: number; ignored: number; at: Date } | undefined;
/** So automatic scans only notify when new vulnerable packages show up. */
let notifiedKeys = new Set<string>();

/** Automatic retries when an automatic scan fails because of the network. */
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
  setStatus('$(shield) Canary', 'Click to see the vulnerabilities');
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

  // re-scan when manifests change (editor save, npm install, pip freeze...)
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

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

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
        title: 'Canary: scanning dependencies',
        cancellable: manual,
      },
      async (progress, token) => {
        const abort = new AbortController();
        token.onCancellationRequested(() => abort.abort());

        progress.report({ message: 'looking for manifests…' });
        const collected = await collectDependencies();
        // ignored packages are never sent to OSV.dev
        const isIgnored = compileIgnorePatterns(config().get<string[]>('ignorePackages', []));
        const deps = collected.filter((d) => !isIgnored(d));
        if (deps.length < collected.length) {
          output.appendLine(
            `[info] ${collected.length - deps.length} ${plural(collected.length - deps.length, 'dependency', 'dependencies')} ignored by canary.ignorePackages (not sent to OSV.dev)`,
          );
        }
        if (token.isCancellationRequested) {
          return undefined;
        }
        progress.report({ message: `querying OSV.dev (${deps.length} packages)…` });
        const start = Date.now();
        const findings = await osv.scan(deps, abort.signal);
        publish(findings);

        const total = findings.reduce((n, f) => n + f.vulnerabilities.length, 0);
        output.appendLine(
          `[${new Date().toLocaleTimeString()}] ${deps.length} dependencies scanned, ` +
            `${findings.length} vulnerable packages, ${total} vulnerabilities (${Date.now() - start} ms)`,
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
    output.appendLine(`[error] scan failed: ${msg}`);
    // keep the previous results (if any) and show the problem in the status bar
    setStatus('$(warning) Canary: no connection', `${msg}\n\nClick to scan again.`);
    status.command = 'canary.scan';
    if (manual) {
      void vscode.window.showErrorMessage(`Canary: scan failed — ${msg}`, 'Try again', 'Show log').then((choice) => {
        if (choice === 'Try again') {
          void runScan(true);
        } else if (choice === 'Show log') {
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

/** Automatic scan failed: silently retries, with increasing intervals. */
function scheduleAutoRetry(): void {
  clearTimeout(autoRetryTimer);
  const delay = AUTO_RETRY_DELAYS_MS[autoRetryCount];
  if (delay === undefined) {
    output.appendLine('[error] automatic retries exhausted; use "Canary: Scan for vulnerabilities".');
    return;
  }
  autoRetryCount++;
  output.appendLine(`[info] next automatic scan in ${delay / 1000}s`);
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

  // 1) JS projects with a lockfile (pnpm and yarn take precedence over package-lock.json in the same folder)
  const jsLocked = await settle([
    ...[...pnpmLockDirs].map((d) => parsePnpmProject(d, { includeDev })),
    ...[...yarnLockDirs].filter((d) => !pnpmLockDirs.has(d)).map((d) => parseYarnProject(d, { includeDev })),
    ...[...npmLockDirs].filter((d) => !pnpmLockDirs.has(d) && !yarnLockDirs.has(d)).map((d) => parseNpmProject(d, { includeDev })),
  ]);
  // 2) package.json without a lockfile, skipping workspace members already covered by a lockfile
  const members = new Set(jsLocked.flatMap((r) => r.members));
  const jsLoose = await settle(
    [...npmDirs]
      .filter((d) => !npmLockDirs.has(d) && !pnpmLockDirs.has(d) && !yarnLockDirs.has(d) && !members.has(d))
      .map((d) => parseNpmProject(d, { includeDev })),
  );

  // members of a uv workspace are already in the root uv.lock: do not scan them again
  const coveredByLock = (dir: string) =>
    [...uvLockDirs].some((lockDir) => lockDir !== dir && (dir + path.sep).startsWith(lockDir + path.sep));
  const uvDirs = new Set([...uvLockDirs, ...[...pyprojectDirs].filter((d) => !uvLockDirs.has(d) && !coveredByLock(d))]);
  const python = await settle([
    ...[...uvDirs].map((d) => parseUvProject(d, { includeDev })),
    ...reqFiles.map((f) => parseRequirements(f)),
  ]);

  for (const reason of failures) {
    output.appendLine(`[warn] could not read a manifest: ${reason}`);
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
      const fix = v.fixedVersion ? ` Fixed in ${v.fixedVersion}.` : ' No known fixed version.';
      const approx = d.approximate ? ` (version estimated from "${d.spec}")` : '';
      const via = d.direct ? '' : ' [transitive]';
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
    setStatus('$(shield) 0 vulnerabilities', 'No known vulnerabilities found');
    status.backgroundColor = undefined;
    return;
  }
  const worst = findings.map((f) => maxSeverity(f.vulnerabilities)).reduce<Severity>(
    (m, s) => (SEVERITY_ORDER[s] > SEVERITY_ORDER[m] ? s : m),
    'UNKNOWN',
  );
  setStatus(`$(shield) ${total} vulnerabilit${total > 1 ? 'ies' : 'y'}`, `Worst severity: ${worst}. Click for details.`);
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
  setStatus('$(shield) Canary', 'Click to see the vulnerabilities');
}

/**
 * Badge over the Canary icon in the activity bar: number of vulnerable packages
 * (the same entries as the panel). With no value, VS Code hides the badge.
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
      `${packages} package${packages > 1 ? 's' : ''} with vulnerabilities ` +
      `(${vulns} vulnerabilit${vulns > 1 ? 'ies' : 'y'} in total)`,
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

/** Quick Fix: bumps the version to the lowest one that fixes all known vulnerabilities of the package. */
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
        const open = new vscode.CodeAction(`Open advisory ${vuln.id}`, vscode.CodeActionKind.QuickFix);
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
    return undefined; // transitive: the package that pulls it in must be updated (or use "overrides")
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
    `Update ${dep.name} to ${replacement}` +
    (dep.manager === 'uv' ? ' in pyproject.toml (then run "uv lock")' : '') +
    (dep.manager === 'pnpm' ? ' in package.json (then run "pnpm install")' : '') +
    (dep.manager === 'yarn' ? ' in package.json (then run "yarn install")' : '') +
    (dep.manager === 'npm' ? ' in package.json (then run "npm install")' : '') +
    (unfixed ? ` (${unfixed} ${plural(unfixed, 'vulnerability', 'vulnerabilities')} still without a fix)` : '');
  const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
  action.edit = new vscode.WorkspaceEdit();
  action.edit.replace(doc.uri, range, replacement);
  action.diagnostics = [diag];
  action.isPreferred = true;
  return action;
}

/**
 * uv: "uv lock --upgrade-package <name>" also works for transitive dependencies,
 * as long as the pyproject.toml constraints allow the fixed version.
 */
function uvLockAction(finding: Finding, diag: vscode.Diagnostic): vscode.CodeAction | undefined {
  const dep = finding.dependency;
  if (dep.manager !== 'uv' || !dep.projectDir || dep.approximate) {
    return undefined;
  }
  // runs a command in the terminal: only in trusted folders and with a valid package name
  if (!vscode.workspace.isTrusted || !isSafePyPackageName(dep.name)) {
    return undefined;
  }
  if (!finding.vulnerabilities.some((v) => v.fixedVersion)) {
    return undefined;
  }
  const action = new vscode.CodeAction(
    `Run "uv lock --upgrade-package ${dep.name}" in the terminal`,
    vscode.CodeActionKind.QuickFix,
  );
  action.command = { command: 'canary.uvUpgrade', title: 'uv lock --upgrade-package', arguments: [dep.projectDir, dep.name] };
  action.diagnostics = [diag];
  action.isPreferred = !dep.versionLocation;
  return action;
}

/**
 * Runs "uv lock --upgrade-package <package>". Takes only the folder and the name (never a ready-made command)
 * and revalidates everything, because commands can be invoked with arbitrary arguments.
 */
function uvUpgrade(projectDir: unknown, packageName: unknown): void {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage('Canary: trust this folder (Workspace Trust) to run commands in the terminal.');
    return;
  }
  if (typeof projectDir !== 'string' || typeof packageName !== 'string' || !isSafePyPackageName(packageName)) {
    void vscode.window.showErrorMessage('Canary: invalid package name; command not run.');
    return;
  }
  if (!vscode.workspace.getWorkspaceFolder(vscode.Uri.file(projectDir))) {
    void vscode.window.showErrorMessage('Canary: the project folder is outside the workspace; command not run.');
    return;
  }
  const terminal = vscode.window.createTerminal({ name: 'Canary', cwd: projectDir });
  terminal.show();
  terminal.sendText(`uv lock --upgrade-package ${packageName}`);
}

// ---------------------------------------------------------------------------
// Notification and report
// ---------------------------------------------------------------------------

const ACTION_EXPORT = 'Export report';
const ACTION_RESCAN = 'Scan again';
const ACTION_DETAILS = 'View details';

/**
 * Manual scan: always notifies. Automatic scan (on open or when a lockfile changes): only notifies
 * when a vulnerable package shows up that has not been notified yet.
 */
function notifyResult(findings: Finding[], total: number, dependencies: number, manual: boolean): void {
  const keys = new Set(findings.map((f) => `${f.dependency.location.file}|${f.dependency.name}@${f.dependency.version}`));
  const hasNew = [...keys].some((k) => !notifiedKeys.has(k));
  notifiedKeys = keys;

  if (!findings.length) {
    if (manual) {
      void vscode.window
        .showInformationMessage(`Canary: no known vulnerabilities in ${dependencies} ${plural(dependencies, 'dependency', 'dependencies')}.`, ACTION_RESCAN)
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
      ['CRITICAL', 'critical'],
      ['HIGH', 'high'],
      ['MODERATE', 'medium'],
      ['LOW', 'low'],
    ] as [Severity, string][]
  )
    .filter(([s]) => counts[s])
    .map(([s, label]) => `${counts[s]} ${label}`);
  const message =
    `Canary: ${findings.length} ${plural(findings.length, 'package', 'packages')} with ${total} ${plural(total, 'vulnerability', 'vulnerabilities')}` + (parts.length ? ` — ${parts.join(', ')}.` : '.');

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
  { format: 'markdown', label: '$(markdown) Markdown', description: 'Readable, good for PRs, issues and documentation', ext: 'md', filter: 'Markdown' },
  { format: 'csv', label: '$(table) CSV', description: 'To open in Excel, Google Sheets or LibreOffice', ext: 'csv', filter: 'CSV' },
  { format: 'json', label: '$(json) JSON', description: 'To integrate with other tools and CI', ext: 'json', filter: 'JSON' },
];

async function exportReport(): Promise<void> {
  if (!lastScan) {
    const choice = await vscode.window.showInformationMessage(
      'Canary: no scan has completed yet. Scan now?',
      ACTION_RESCAN,
    );
    if (choice === ACTION_RESCAN) {
      await runScan(true);
    }
    return;
  }
  const scan = lastScan;
  const picked = await vscode.window.showQuickPick(FORMATS, {
    title: 'Canary: export vulnerability report',
    placeHolder: 'Choose the format',
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
    saveLabel: 'Export',
    title: 'Save Canary report',
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
    void vscode.window.showErrorMessage(`Canary: could not save the report — ${err?.message ?? err}`);
    return;
  }
  output.appendLine(`[info] report exported: ${target.fsPath}`);

  const open = picked.format === 'markdown' ? 'Open preview' : 'Open';
  const choice = await vscode.window.showInformationMessage(
    `Canary: report saved to ${vscode.workspace.asRelativePath(target)}.`,
    open,
    'Reveal in folder',
  );
  if (choice === 'Open preview') {
    await vscode.commands.executeCommand('markdown.showPreview', target);
  } else if (choice === 'Open') {
    await vscode.window.showTextDocument(target);
  } else if (choice === 'Reveal in folder') {
    await vscode.commands.executeCommand('revealFileInOS', target);
  }
}
