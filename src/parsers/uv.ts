import * as fs from 'fs/promises';
import * as path from 'path';
import { Dependency, Location } from '../types';
import { normalizePyName, parseRequirementSpec } from './python';

export interface UvOptions {
  includeDev: boolean;
}

/** Uma dependência declarada no pyproject.toml, com a posição exata da string. */
interface Declared {
  name: string;
  raw: string;
  dev: boolean;
  location: Location;
  versionLocation?: Location;
  version?: string;
  approximate: boolean;
  spec: string;
}

/**
 * Projeto uv (ou qualquer projeto PEP 621): pyproject.toml + uv.lock opcional.
 * Com uv.lock: versões exatas de todas as dependências, inclusive transitivas.
 * Sem uv.lock: usa os specifiers do pyproject.toml (versões aproximadas).
 */
export async function parseUvProject(dir: string, opts: UvOptions): Promise<Dependency[]> {
  const pyprojectPath = path.join(dir, 'pyproject.toml');
  const lockPath = path.join(dir, 'uv.lock');
  const [pyText, lockText] = await Promise.all([readOptional(pyprojectPath), readOptional(lockPath)]);

  const declared = pyText ? parsePyproject(pyprojectPath, pyText) : [];
  if (lockText) {
    return parseUvLock(lockPath, lockText, declared, opts, dir);
  }
  return declared
    .filter((d) => d.version && (opts.includeDev || !d.dev))
    .map((d) => ({
      name: d.name,
      version: d.version!,
      ecosystem: 'PyPI' as const,
      manager: 'uv' as const,
      projectDir: dir,
      location: d.location,
      versionLocation: d.versionLocation,
      spec: d.spec,
      direct: true,
      dev: d.dev,
      approximate: d.approximate,
    }));
}

async function readOptional(file: string): Promise<string | undefined> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// pyproject.toml
// ---------------------------------------------------------------------------

/**
 * Leitor de TOML restrito ao necessário: arrays de strings em
 *   [project] dependencies, [project.optional-dependencies] *,
 *   [dependency-groups] * e [tool.uv] dev-dependencies.
 * Guarda a linha/coluna de cada string para os diagnostics e o Quick Fix.
 */
export function parsePyproject(file: string, text: string): Declared[] {
  const out: Declared[] = [];
  const lines = text.split(/\r?\n/);
  let table = '';
  let inArray: { dev: boolean } | undefined;
  let depth = 0;

  lines.forEach((line, lineNo) => {
    if (!inArray) {
      const header = /^\s*\[([^\[\]]+)\]\s*(#.*)?$/.exec(line);
      if (header) {
        table = header[1].trim();
        return;
      }
      const key = /^\s*("?)([A-Za-z0-9_.-]+)\1\s*=\s*\[/.exec(line);
      if (!key) {
        return;
      }
      const k = key[2];
      const isDeps =
        (table === 'project' && k === 'dependencies') ||
        table === 'project.optional-dependencies' ||
        table === 'dependency-groups' ||
        (table === 'tool.uv' && k === 'dev-dependencies');
      if (!isDeps) {
        return;
      }
      inArray = { dev: table === 'dependency-groups' || table === 'tool.uv' };
      depth = 0;
      const start = line.indexOf('[', key[0].length - 1);
      scan(line, lineNo, start);
      return;
    }
    scan(line, lineNo, 0);
  });

  /** Percorre a linha coletando strings e contando colchetes fora delas. */
  function scan(line: string, lineNo: number, from: number) {
    let braces = 0;
    for (let i = from; i < line.length && inArray; i++) {
      const c = line[i];
      if (c === '#') {
        break;
      }
      if (c === '"' || c === "'") {
        const end = line.indexOf(c, i + 1);
        if (end < 0) {
          break;
        }
        if (braces === 0) {
          addDeclared(line.slice(i + 1, end), lineNo, i + 1, inArray.dev);
        }
        i = end;
      } else if (c === '{') {
        braces++; // ex.: { include-group = "test" }
      } else if (c === '}') {
        braces--;
      } else if (c === '[') {
        depth++;
      } else if (c === ']') {
        depth--;
        if (depth === 0) {
          inArray = undefined;
        }
      }
    }
  }

  function addDeclared(raw: string, line: number, col: number, dev: boolean) {
    const spec = parseRequirementSpec(raw);
    if (!spec || raw.includes(' @ ')) {
      return;
    }
    out.push({
      name: spec.name,
      raw,
      dev,
      location: { file, line, startCol: col - 1, endCol: col + raw.length + 1 },
      versionLocation:
        spec.versionOffset !== undefined
          ? { file, line, startCol: col + spec.versionOffset, endCol: col + spec.versionOffset + spec.rawVersion!.length }
          : undefined,
      version: spec.version,
      approximate: spec.approximate,
      spec: raw,
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// uv.lock
// ---------------------------------------------------------------------------

interface LockPackage {
  name: string;
  version?: string;
  line: number;
  startCol: number;
  endCol: number;
  source: string;
  deps: string[];
  devDeps: string[];
}

/** Leitor linha a linha do uv.lock (formato estável e gerado pela ferramenta). */
export function parseUvLock(lockPath: string, text: string, declared: Declared[], opts: UvOptions, dir: string): Dependency[] {
  const packages: LockPackage[] = [];
  let cur: LockPackage | undefined;
  let section: 'top' | 'deps' | 'dev' | 'other' = 'other';
  let collecting: 'deps' | 'dev' | undefined;

  text.split(/\r?\n/).forEach((line, lineNo) => {
    if (/^\[\[package\]\]\s*$/.test(line)) {
      cur = { name: '', line: lineNo, startCol: 0, endCol: line.length, source: '', deps: [], devDeps: [] };
      packages.push(cur);
      section = 'top';
      collecting = undefined;
      return;
    }
    const header = /^\[\[?([^\]]+)\]\]?\s*$/.exec(line);
    if (header) {
      const h = header[1];
      section = h === 'package.optional-dependencies' ? 'deps' : h === 'package.dev-dependencies' ? 'dev' : 'other';
      if (!h.startsWith('package.')) {
        cur = undefined;
      }
      collecting = undefined;
      return;
    }
    if (!cur) {
      return;
    }

    if (collecting) {
      collectNames(line, collecting === 'deps' ? cur.deps : cur.devDeps);
      if (line.trim().startsWith(']')) {
        collecting = undefined;
      }
      return;
    }

    if (section === 'top') {
      const kv = /^(name|version|source)\s*=\s*(.*)$/.exec(line);
      if (kv) {
        if (kv[1] === 'name') {
          cur.name = unquote(kv[2]);
          cur.line = lineNo;
          cur.startCol = line.indexOf('"');
          cur.endCol = line.lastIndexOf('"') + 1;
        } else if (kv[1] === 'version') {
          cur.version = unquote(kv[2]);
        } else {
          cur.source = kv[2];
        }
        return;
      }
      if (/^dependencies\s*=\s*\[/.test(line)) {
        startArray(line, 'deps');
      }
    } else if (section === 'deps' || section === 'dev') {
      if (/^[A-Za-z0-9_."-]+\s*=\s*\[/.test(line)) {
        startArray(line, section);
      }
    }
  });

  function startArray(line: string, target: 'deps' | 'dev') {
    collectNames(line, target === 'deps' ? cur!.deps : cur!.devDeps);
    if (!/\]\s*$/.test(line)) {
      collecting = target; // array multilinha: termina numa linha que começa com "]"
    }
  }

  // projetos locais (raiz, membros de workspace) definem o que é dependência direta
  const isLocal = (p: LockPackage) => /\b(editable|virtual|directory|path)\s*=/.test(p.source);
  const directDeps = new Set<string>();
  const directDev = new Set<string>();
  for (const p of packages.filter(isLocal)) {
    p.deps.forEach((d) => directDeps.add(d));
    p.devDeps.forEach((d) => directDev.add(d));
  }
  const declaredByName = new Map<string, Declared>();
  for (const d of declared) {
    if (!declaredByName.has(d.name)) {
      declaredByName.set(d.name, d);
    }
  }

  const out: Dependency[] = [];
  for (const p of packages) {
    if (!p.name || !p.version || isLocal(p) || !/\bregistry\s*=/.test(p.source)) {
      continue; // pacotes git/url/locais não são consultados
    }
    const name = normalizePyName(p.name);
    const direct = directDeps.has(name) || directDev.has(name);
    const dev = !directDeps.has(name) && directDev.has(name);
    if (dev && !opts.includeDev) {
      continue;
    }
    const decl = direct ? declaredByName.get(name) : undefined;
    out.push({
      name,
      version: p.version,
      ecosystem: 'PyPI',
      manager: 'uv',
      projectDir: dir,
      location: decl?.location ?? { file: lockPath, line: p.line, startCol: p.startCol, endCol: p.endCol },
      versionLocation: decl?.versionLocation,
      spec: decl?.spec ?? `==${p.version}`,
      direct,
      dev,
      approximate: false,
    });
  }
  return out;
}

function collectNames(line: string, into: string[]) {
  for (const m of line.matchAll(/\bname\s*=\s*"([^"]+)"/g)) {
    into.push(normalizePyName(m[1]));
  }
}

function unquote(v: string): string {
  return v.trim().replace(/^"(.*)"$/, '$1');
}
