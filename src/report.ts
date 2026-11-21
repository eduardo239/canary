import { Finding, Severity, SEVERITY_ORDER } from './types';
import { compareVersions } from './version';

export type ReportFormat = 'markdown' | 'csv' | 'json';

export interface ReportMeta {
  generatedAt: Date;
  /** nome do workspace (só aparece no relatório local, nunca é enviado para fora) */
  workspace: string;
  dependenciesScanned: number;
  ignored: number;
  /** converte caminho absoluto em caminho relativo ao workspace */
  relativePath: (file: string) => string;
}

/** Uma linha do relatório: uma vulnerabilidade de um pacote em um local. */
export interface ReportRow {
  package: string;
  ecosystem: string;
  manager: string;
  currentVersion: string;
  declaredAs: string;
  versionEstimated: boolean;
  dependencyType: 'direta' | 'transitiva' | 'dev';
  file: string;
  line: number;
  vulnerabilityId: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  /** menor versão que corrige esta vulnerabilidade */
  fixedVersion: string | null;
  /** menor versão que corrige todas as vulnerabilidades conhecidas do pacote */
  recommendedVersion: string | null;
  published: string | null;
  url: string;
}

/** Menor versão que corrige todas as vulnerabilidades com correção conhecida (a maior entre as correções). */
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
        dependencyType: d.direct ? (d.dev ? 'dev' : 'direta') : 'transitiva',
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

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MODERATE: 'Média',
  LOW: 'Baixa',
  UNKNOWN: 'Desconhecida',
};

const CVE = (aliases: string[]) => aliases.filter((a) => a.startsWith('CVE-'));

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

function toMarkdown(rows: ReportRow[], findings: Finding[], meta: ReportMeta): string {
  const counts = severityCounts(rows);
  const cell = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').trim();
  const out: string[] = [];

  out.push('# Relatório de vulnerabilidades — Canary', '');
  out.push(`- **Workspace:** ${cell(meta.workspace)}`);
  out.push(`- **Gerado em:** ${formatDate(meta.generatedAt)}`);
  out.push(`- **Dependências analisadas:** ${meta.dependenciesScanned}` + (meta.ignored ? ` (${meta.ignored} ignoradas)` : ''));
  out.push(`- **Pacotes vulneráveis:** ${findings.length}`);
  out.push(`- **Vulnerabilidades:** ${rows.length}`);
  out.push('- **Fonte:** [OSV.dev](https://osv.dev)', '');

  out.push('## Resumo por severidade', '');
  out.push('| Severidade | Quantidade |', '|---|---:|');
  (Object.keys(counts) as Severity[]).filter((s) => counts[s]).forEach((s) => out.push(`| ${SEVERITY_LABEL[s]} | ${counts[s]} |`));
  out.push('');

  // um pacote por linha: o que fazer
  out.push('## Pacotes e correções recomendadas', '');
  out.push('| Pacote | Versão atual | Atualizar para | Pior severidade | Vulnerabilidades | Tipo | Local |');
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
      `| \`${cell(d.name)}\` (${d.manager}) | ${cell(d.version)}${d.approximate ? ' ⚠️ estimada' : ''} | ` +
        `${rec ? `**${cell(rec)}**` : 'sem correção'}${rec && unfixed ? ` (${unfixed} sem correção)` : ''} | ` +
        `${SEVERITY_LABEL[worst(f)]} | ${f.vulnerabilities.length} | ` +
        `${d.direct ? (d.dev ? 'dev' : 'direta') : 'transitiva'} | \`${cell(meta.relativePath(d.location.file))}:${d.location.line + 1}\` |`,
    );
  }
  out.push('');

  // uma vulnerabilidade por linha: detalhes
  out.push('## Vulnerabilidades', '');
  out.push('| Severidade | ID | CVE | Pacote | Versão atual | Corrigida em | Resumo |');
  out.push('|---|---|---|---|---|---|---|');
  for (const r of rows) {
    out.push(
      `| ${SEVERITY_LABEL[r.severity]} | [${cell(r.vulnerabilityId)}](${r.url}) | ${cell(CVE(r.aliases).join(', ')) || '—'} | ` +
        `\`${cell(r.package)}\` | ${cell(r.currentVersion)} | ${r.fixedVersion ? cell(r.fixedVersion) : '—'} | ${cell(r.summary)} |`,
    );
  }
  out.push('');
  out.push(
    '> A ausência de uma vulnerabilidade neste relatório não garante que ela não exista: ' +
      'o Canary só conhece o que está catalogado na OSV.dev.',
    '',
  );
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

const CSV_COLUMNS: [keyof ReportRow | 'cve', string][] = [
  ['severity', 'severidade'],
  ['package', 'pacote'],
  ['ecosystem', 'ecossistema'],
  ['manager', 'gerenciador'],
  ['currentVersion', 'versao_atual'],
  ['fixedVersion', 'versao_corrigida'],
  ['recommendedVersion', 'versao_recomendada'],
  ['declaredAs', 'declarado_como'],
  ['versionEstimated', 'versao_estimada'],
  ['dependencyType', 'tipo'],
  ['vulnerabilityId', 'id'],
  ['cve', 'cve'],
  ['aliases', 'aliases'],
  ['summary', 'resumo'],
  ['published', 'publicado_em'],
  ['file', 'arquivo'],
  ['line', 'linha'],
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
  // BOM para o Excel reconhecer UTF-8 (acentos)
  return '\uFEFF' + lines.join('\r\n') + '\r\n';
}

/**
 * Escapa um campo CSV. Textos vindos de fora (resumos da OSV, nomes de pacotes) que começam com
 * "=", "+", "-", "@" ou tab/CR seriam interpretados como fórmula por planilhas (CSV injection):
 * nesses casos o valor recebe um apóstrofo na frente.
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
