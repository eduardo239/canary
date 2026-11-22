import * as fs from 'fs/promises';
import { Dependency } from '../types';
import { versionFromSpec } from '../version';

/** PEP 503 name normalization (Requests_OAuthlib -> requests-oauthlib). */
export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

const REQ_RE = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(===|==|~=|>=|>|<=|<|!=)?\s*([^\s;,#]+)?/;

export interface RequirementSpec {
  /** normalized name */
  name: string;
  op?: string;
  rawVersion?: string;
  /** concrete version to query (when it can be inferred) */
  version?: string;
  approximate: boolean;
  /** position of the version inside the parsed string */
  versionOffset?: number;
}

/** Parses a PEP 508 requirement ("requests[socks]>=2.25,<3 ; python_version>'3.8'"). */
export function parseRequirementSpec(text: string): RequirementSpec | undefined {
  const m = REQ_RE.exec(text.trim());
  if (!m) {
    return undefined;
  }
  const [, rawName, op, rawVersion] = m;
  const spec: RequirementSpec = { name: normalizePyName(rawName), op, rawVersion, approximate: true };
  if (op && rawVersion && ['==', '===', '>=', '~='].includes(op)) {
    const exact = op === '==' || op === '===';
    const version = exact ? rawVersion.replace(/\.\*$/, '') : versionFromSpec(rawVersion);
    if (version && !version.includes('*')) {
      spec.version = version;
      spec.approximate = !exact || rawVersion.endsWith('.*');
      const lead = text.length - text.trimStart().length;
      const at = text.indexOf(rawVersion, lead + rawName.length);
      spec.versionOffset = at >= 0 ? at : undefined;
    }
  }
  return spec;
}

/**
 * Reads a requirements*.txt. Uses the exact version for "==" and, for ">=" and "~=",
 * the minimum version (flagged as approximate). Other forms are ignored.
 */
export async function parseRequirements(file: string): Promise<Dependency[]> {
  const text = await fs.readFile(file, 'utf8');
  const out: Dependency[] = [];
  text.split(/\r?\n/).forEach((raw, line) => {
    const content = raw.replace(/\s+#.*$/, '').replace(/^\s*#.*$/, '');
    const trimmed = content.trim();
    if (!trimmed || trimmed.startsWith('-') || /^[a-z+]+:\/\//i.test(trimmed) || trimmed.includes(' @ ')) {
      return;
    }
    const spec = parseRequirementSpec(content);
    if (!spec?.version) {
      return;
    }
    const indent = raw.length - raw.trimStart().length;
    out.push({
      name: spec.name,
      version: spec.version,
      ecosystem: 'PyPI',
      manager: 'pip',
      location: { file, line, startCol: indent, endCol: indent + trimmed.length },
      versionLocation:
        spec.versionOffset !== undefined
          ? { file, line, startCol: spec.versionOffset, endCol: spec.versionOffset + spec.rawVersion!.length }
          : undefined,
      spec: `${spec.op}${spec.rawVersion}`,
      direct: true,
      dev: false,
      approximate: spec.approximate,
    });
  });
  return out;
}
