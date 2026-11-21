import { normalizePyName } from './parsers/python';
import { Dependency, Ecosystem, Finding, Severity, SEVERITY_ORDER, Vulnerability } from './types';
import { compareVersions } from './version';
import { isSafeVersion } from './security';

const API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;
const TIMEOUT_MS = 30_000;

interface OsvVuln {
  id: string;
  modified?: string;
  published?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: Record<string, string>[] }[];
    database_specific?: { severity?: string };
  }[];
}

/** Cliente da API OSV.dev (https://google.github.io/osv.dev/api/). Mantém cache dos detalhes. */
export class OsvClient {
  private readonly cache = new Map<string, OsvVuln>();

  async scan(deps: Dependency[], signal?: AbortSignal): Promise<Finding[]> {
    // agrupa dependências iguais para não repetir consultas
    const groups = new Map<string, Dependency[]>();
    for (const d of deps) {
      const key = `${d.ecosystem}|${d.name}|${d.version}`;
      const list = groups.get(key);
      list ? list.push(d) : groups.set(key, [d]);
    }
    const keys = [...groups.keys()];
    const idsByKey = new Map<string, { id: string; modified?: string }[]>();

    for (let i = 0; i < keys.length; i += BATCH_SIZE) {
      const chunk = keys.slice(i, i + BATCH_SIZE);
      const body = {
        queries: chunk.map((k) => {
          const d = groups.get(k)![0];
          return { package: { name: d.name, ecosystem: d.ecosystem }, version: d.version };
        }),
      };
      const res = await this.request<{ results: { vulns?: { id: string; modified?: string }[] }[] }>(
        '/querybatch',
        { method: 'POST', body: JSON.stringify(body) },
        signal,
      );
      res.results.forEach((r, j) => {
        if (r.vulns?.length) {
          idsByKey.set(chunk[j], r.vulns);
        }
      });
    }

    // busca detalhes só do que não está em cache (ou foi modificado)
    const toFetch = new Set<string>();
    for (const list of idsByKey.values()) {
      for (const v of list) {
        const cached = this.cache.get(v.id);
        if (!cached || (v.modified && cached.modified !== v.modified)) {
          toFetch.add(v.id);
        }
      }
    }
    await mapLimit([...toFetch], DETAIL_CONCURRENCY, async (id) => {
      const vuln = await this.request<OsvVuln>(`/vulns/${encodeURIComponent(id)}`, { method: 'GET' }, signal);
      this.cache.set(id, vuln);
    });

    const findings: Finding[] = [];
    for (const [key, list] of idsByKey) {
      const sample = groups.get(key)![0];
      const vulns = dedupe(
        list
          .map((v) => this.cache.get(v.id))
          .filter((v): v is OsvVuln => !!v)
          .map((v) => toVulnerability(v, sample.name, sample.ecosystem, sample.version)),
      );
      for (const dependency of groups.get(key)!) {
        findings.push({ dependency, vulnerabilities: vulns });
      }
    }
    return findings;
  }

  private async request<T>(path: string, init: RequestInit, signal?: AbortSignal): Promise<T> {
    const timeout = AbortSignal.timeout(TIMEOUT_MS);
    const res = await fetch(API + path, {
      ...init,
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'canary-vscode' },
      signal: signal ? anySignal([signal, timeout]) : timeout,
    });
    if (!res.ok) {
      throw new Error(`OSV.dev respondeu ${res.status} ${res.statusText} em ${path}`);
    }
    return (await res.json()) as T;
  }
}

function toVulnerability(v: OsvVuln, name: string, ecosystem: Ecosystem, version: string): Vulnerability {
  const same = (n: string) => (ecosystem === 'PyPI' ? normalizePyName(n) === normalizePyName(name) : n === name);
  const affected = (v.affected ?? []).filter((a) => a.package && a.package.ecosystem === ecosystem && same(a.package.name));

  const fixes: string[] = [];
  for (const a of affected) {
    for (const r of a.ranges ?? []) {
      if (r.type === 'GIT') {
        continue;
      }
      for (const e of r.events) {
        if (e.fixed) {
          fixes.push(e.fixed);
        }
      }
    }
  }
  // a versão corrigida pode ser escrita no manifesto pelo Quick Fix: só aceita caracteres de versão
  const fixedVersion = fixes
    .filter((f) => isSafeVersion(f) && compareVersions(f, version) > 0)
    .sort(compareVersions)[0];

  const rawSeverity = v.database_specific?.severity ?? affected.find((a) => a.database_specific?.severity)?.database_specific?.severity;

  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary?.trim() || v.details?.split('\n')[0].trim() || v.id,
    severity: normalizeSeverity(rawSeverity, v.severity),
    fixedVersion,
    url: `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`,
    published: v.published,
  };
}

function normalizeSeverity(raw: string | undefined, scores: OsvVuln['severity']): Severity {
  switch (raw?.toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MODERATE':
    case 'MEDIUM':
      return 'MODERATE';
    case 'LOW':
      return 'LOW';
  }
  // fallback: nota numérica da CVSS, quando vier como número
  const numeric = scores?.map((s) => parseFloat(s.score)).find((n) => !isNaN(n));
  if (numeric !== undefined) {
    return numeric >= 9 ? 'CRITICAL' : numeric >= 7 ? 'HIGH' : numeric >= 4 ? 'MODERATE' : 'LOW';
  }
  return 'UNKNOWN';
}

/** Remove duplicatas (ex.: GHSA-xxx e PYSEC-yyy descrevendo o mesmo CVE), preferindo a que tem severidade. */
function dedupe(vulns: Vulnerability[]): Vulnerability[] {
  const sorted = [...vulns].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  const seen = new Set<string>();
  const out: Vulnerability[] = [];
  for (const v of sorted) {
    if (seen.has(v.id) || v.aliases.some((a) => seen.has(a))) {
      continue;
    }
    seen.add(v.id);
    v.aliases.forEach((a) => seen.add(a));
    out.push(v);
  }
  return out;
}

async function mapLimit<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      await fn(items[next++]);
    }
  });
  await Promise.all(workers);
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener('abort', () => controller.abort(s.reason), { once: true });
  }
  return controller.signal;
}
