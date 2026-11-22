import { Finding, Severity, SEVERITY_ORDER } from './types';
import { compareVersions } from './version';

export type ReportFormat = 'markdown' | 'csv' | 'json';

export interface ReportMeta {
  generatedAt: Date;
  /** workspace name (only appears in the local report, never sent anywhere) */
  workspace: string;
  dependenciesScanned: number;
  ignored: number;
  /** converts an absolute path to a workspace-relative path */
  relativePath: (file: string) => string;
}

/** One report row: one vulnerability of a package at one location. */
export interface ReportRow {
  package: string;
  ecosystem: string;
  manager: string;
  currentVersion: string;
  declaredAs: string;
  versionEstimated: boolean;
  dependencyType: 'direct' | 'transitive' | 'dev';
  file: string;
  line: number;
  vulnerabilityId: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  /** lowest version that fixes this vulnerability */
  fixedVersion: string | null;
  /** lowest version that fixes all known vulnerabilities of the package */
  recommendedVersion: string | null;
  published: string | null;
  url: string;
}

/** Lowest version that fixes every vulnerability with a known fix (the highest of the fixes). */
export function recommendedVersion(finding: Finding): string | undefined {
  const fixes = finding.vulnerabilities.map((v) => v.fixedVersion).filter((v): v is string => !!v);
  return fixes.length ? [...fixes].sort(compareVersions)[fixes.length - 1] : undefined;
}

export function buildRows(findings: Finding[], meta: ReportMeta): ReportRow[] {
  const rows: ReportRow[] = [];
  for (const f of findings) {
    const d = f.dependency;
    const recommended = recommendedVersion(f) ?? null;
    for (const v of f.vulnerabilities) {
      rows.push({
        package: d.name,
        ecosystem: d.ecosystem,
        manager: d.manager,
        currentVersion: d.version,
        declaredAs: d.spec,
        versionEstimated: d.approximate,
        dependencyType: d.direct ? (d.dev ? 'dev' : 'direct') : 'transitive',
        file: meta.relativePath(d.location.file),
        line: d.location.line + 1,
        vulnerabilityId: v.id,
        aliases: v.aliases,
        severity: v.severity,
        summary: v.summary,
        fixedVersion: v.fixedVersion ?? null,
        recommendedVersion: recommended,
        published: v.published ?? null,
        url: v.url,
      });
    }
  }
  return rows.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.package.localeCompare(b.package) ||
      a.file.localeCompare(b.file) ||
      a.vulnerabilityId.localeCompare(b.vulnerabilityId),
  );
}

export function severityCounts(rows: ReportRow[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
  rows.forEach((r) => counts[r.severity]++);
  return counts;
}

export function renderReport(format: ReportFormat, findings: Finding[], meta: ReportMeta): string {
  const rows = buildRows(findings, meta);
  switch (format) {
    case 'json':
      return toJson(rows, findings, meta);
    case 'csv':
      return toCsv(rows);
    default:
      return toMarkdown(rows, findings, meta);
  }
}

/** Markdown report labels. */
const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MODERATE: 'Medium',
  LOW: 'Low',
  UNKNOWN: 'Unknown',
};

const TYPE_LABEL = (d: { direct: boolean; dev: boolean }) => (d.direct ? (d.dev ? 'dev' : 'direct') : 'transitive');

const CVE = (aliases: string[]) => aliases.filter((a) => a.startsWith('CVE-'));

// ---------------------------------------------------------------------------
// Markdown (for sharing in PRs and issues)
// ---------------------------------------------------------------------------

function toMarkdown(rows: ReportRow[], findings: Finding[], meta: ReportMeta): string {
  const counts = severityCounts(rows);
  const cell = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').trim();
  const out: string[] = [];

  out.push('# Vulnerability Report — Canary', '');
  out.push(`- **Workspace:** ${cell(meta.workspace)}`);
  out.push(`- **Generated:** ${formatDate(meta.generatedAt)}`);
  out.push(`- **Dependencies scanned:** ${meta.dependenciesScanned}` + (meta.ignored ? ` (${meta.ignored} ignored)` : ''));
  out.push(`- **Vulnerable packages:** ${findings.length}`);
  out.push(`- **Vulnerabilities:** ${rows.length}`);
  out.push('- **Source:** [OSV.dev](https://osv.dev)', '');

  out.push('## Summary by severity', '');
  out.push('| Severity | Count |', '|---|---:|');
  (Object.keys(counts) as Severity[]).filter((s) => counts[s]).forEach((s) => out.push(`| ${SEVERITY_LABEL[s]} | ${counts[s]} |`));
  out.push('');

  // one package per row: what to do
  out.push('## Packages and recommended upgrades', '');
  out.push('| Package | Current version | Upgrade to | Highest severity | Vulnerabilities | Type | Location |');
  out.push('|---|---|---|---|---:|---|---|');
  const packages = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[worst(b)] - SEVERITY_ORDER[worst(a)] || a.dependency.name.localeCompare(b.dependency.name),
  );
  for (const f of packages) {
    const d = f.dependency;
    const rec = recommendedVersion(f);
    const unfixed = f.vulnerabilities.filter((v) => !v.fixedVersion).length;
    out.push(
      `| \`${cell(d.name)}\` (${d.manager}) | ${cell(d.version)}${d.approximate ? ' ⚠️ estimated' : ''} | ` +
        `${rec ? `**${cell(rec)}**` : 'no fix available'}${rec && unfixed ? ` (${unfixed} without fix)` : ''} | ` +
        `${SEVERITY_LABEL[worst(f)]} | ${f.vulnerabilities.length} | ` +
        `${TYPE_LABEL(d)} | \`${cell(meta.relativePath(d.location.file))}:${d.location.line + 1}\` |`,
    );
  }
  out.push('');

  // one vulnerability per row: details
  out.push('## Vulnerabilities', '');
  out.push('| Severity | ID | CVE | Package | Current version | Fixed in | Summary |');
  out.push('|---|---|---|---|---|---|---|');
  for (const r of rows) {
    out.push(
      `| ${SEVERITY_LABEL[r.severity]} | [${cell(r.vulnerabilityId)}](${r.url}) | ${cell(CVE(r.aliases).join(', ')) || '—'} | ` +
        `\`${cell(r.package)}\` | ${cell(r.currentVersion)} | ${r.fixedVersion ? cell(r.fixedVersion) : '—'} | ${cell(r.summary)} |`,
    );
  }
  out.push('');
  out.push(
    '> Packages marked as ⚠️ *estimated* have no lockfile; their version was inferred from the declared range.',
    '>',
    '> The absence of a vulnerability in this report does not guarantee it does not exist: ' +
      'Canary only knows what is catalogued in OSV.dev.',
    '',
  );
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

const CSV_COLUMNS: [keyof ReportRow | 'cve', string][] = [
  ['severity', 'severity'],
  ['package', 'package'],
  ['ecosystem', 'ecosystem'],
  ['manager', 'manager'],
  ['currentVersion', 'current_version'],
  ['fixedVersion', 'fixed_version'],
  ['recommendedVersion', 'recommended_version'],
  ['declaredAs', 'declared_as'],
  ['versionEstimated', 'version_estimated'],
  ['dependencyType', 'type'],
  ['vulnerabilityId', 'id'],
  ['cve', 'cve'],
  ['aliases', 'aliases'],
  ['summary', 'summary'],
  ['published', 'published_at'],
  ['file', 'file'],
  ['line', 'line'],
  ['url', 'url'],
];

function toCsv(rows: ReportRow[]): string {
  const lines = [CSV_COLUMNS.map(([, h]) => h).join(',')];
  for (const r of rows) {
    lines.push(
      CSV_COLUMNS.map(([key]) => {
        const value =
          key === 'cve' ? CVE(r.aliases).join(' ') : key === 'aliases' ? r.aliases.join(' ') : (r[key] as unknown);
        return csvField(value === null || value === undefined ? '' : String(value));
      }).join(','),
    );
  }
  // BOM so Excel recognizes UTF-8 (accented characters)
  return '\uFEFF' + lines.join('\r\n') + '\r\n';
}

/**
 * Escapes a CSV field. Externally sourced text (OSV summaries, package names) starting with
 * "=", "+", "-", "@" or tab/CR would be interpreted as a formula by spreadsheets (CSV injection):
 * in those cases the value is prefixed with an apostrophe.
 */
function csvField(value: string): string {
  let v = value;
  if (/^[=+\-@\t\r]/.test(v)) {
    v = `'${v}`;
  }
  return /[",\r\n]/.test(v) || v !== value ? `"${v.replace(/"/g, '""')}"` : v;
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

function toJson(rows: ReportRow[], findings: Finding[], meta: ReportMeta): string {
  return (
    JSON.stringify(
      {
        tool: 'canary',
        source: 'https://osv.dev',
        generatedAt: meta.generatedAt.toISOString(),
        workspace: meta.workspace,
        summary: {
          dependenciesScanned: meta.dependenciesScanned,
          ignored: meta.ignored,
          vulnerablePackages: findings.length,
          vulnerabilities: rows.length,
          bySeverity: severityCounts(rows),
        },
        vulnerabilities: rows,
      },
      null,
      2,
    ) + '\n'
  );
}

function worst(f: Finding): Severity {
  return f.vulnerabilities.reduce<Severity>(
    (m, v) => (SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[m] ? v.severity : m),
    'UNKNOWN',
  );
}

function formatDate(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
