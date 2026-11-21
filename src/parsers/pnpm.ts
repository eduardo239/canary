import * as path from 'path';
import { Dependency, Location, ParseResult } from '../types';
import { ManifestIndex, readOptional } from './npm';

export interface PnpmOptions {
  includeDev: boolean;
}

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;
type Section = (typeof SECTIONS)[number];

interface ImporterDep {
  name: string;
  section: Section;
  ref?: string;
  line: number;
  col: number;
}

interface PkgId {
  name: string;
  /** versão limpa, sem sufixo de peers */
  version: string;
  /** identificador com peers, como aparece no grafo */
  id: string;
}

/**
 * Projeto pnpm: pnpm-lock.yaml (lockfileVersion 5.x, 6.x e 9.x) + package.json dos importers.
 * O lockfile é YAML gerado pela ferramenta, com indentação fixa; o leitor é linha a linha
 * para guardar a posição de cada pacote.
 */
export async function parsePnpmProject(dir: string, opts: PnpmOptions): Promise<ParseResult> {
  const lockPath = path.join(dir, 'pnpm-lock.yaml');
  const text = await readOptional(lockPath);
  if (!text) {
    return { dependencies: [], members: [] };
  }
  const lock = readLock(text);
  const lines = text.split(/\r?\n/);

  const parseId = (raw: string) => parsePkgId(raw, lock.major);
  /** Referência de um importer/snapshot ("1.2.3(peer@1)", "link:..", "alias@1.2.3") -> id do grafo. */
  const resolveRef = (name: string, ref: string): PkgId | undefined => {
    if (/^(link|file|workspace):/.test(ref)) {
      return undefined;
    }
    if (/^\d/.test(ref)) {
      return parseId(lock.major < 6 ? `/${name}/${ref}` : `${name}@${ref}`);
    }
    return parseId(ref); // alias ("string-width@4.2.3") ou id completo ("/name@1.0.0")
  };

  // ---- o que é alcançável a partir das dependências de produção (para marcar dev) ----
  const prodRoots: string[] = [];
  for (const deps of lock.importers.values()) {
    for (const d of deps) {
      const id = d.ref && d.section !== 'devDependencies' ? resolveRef(d.name, d.ref)?.id : undefined;
      if (id) {
        prodRoots.push(id);
      }
    }
  }
  const reachable = new Set<string>();
  const stack = [...prodRoots];
  while (stack.length) {
    const id = stack.pop()!;
    if (reachable.has(id)) {
      continue;
    }
    reachable.add(id);
    for (const [name, ref] of lock.graph.get(id) ?? []) {
      const child = resolveRef(name, ref);
      if (child && !reachable.has(child.id)) {
        stack.push(child.id);
      }
    }
  }

  // ---- dependências diretas: apontam para o package.json de cada importer ----
  const out: Dependency[] = [];
  const directKeys = new Set<string>();
  const members: string[] = [];
  for (const [importer, deps] of lock.importers) {
    const importerDir = path.join(dir, importer);
    if (importer !== '.') {
      members.push(importerDir);
    }
    const pkgPath = path.join(importerDir, 'package.json');
    const pkgText = await readOptional(pkgPath);
    let manifest: ManifestIndex | undefined;
    try {
      manifest = pkgText ? new ManifestIndex(pkgPath, pkgText) : undefined;
    } catch {
      manifest = undefined;
    }
    for (const d of deps) {
      const pkg = d.ref ? resolveRef(d.name, d.ref) : undefined;
      if (!pkg || !/^\d/.test(pkg.version)) {
        continue;
      }
      directKeys.add(`${pkg.name}@${pkg.version}`);
      const dev = d.section === 'devDependencies';
      if (dev && !opts.includeDev) {
        continue;
      }
      const declared = manifest?.declared.get(d.name);
      out.push({
        name: pkg.name,
        version: pkg.version,
        ecosystem: 'npm',
        manager: 'pnpm',
        projectDir: importerDir,
        location: declared?.location ?? lineLocation(lockPath, lines, d.line, d.col),
        versionLocation: declared?.versionLocation,
        spec: declared?.spec ?? pkg.version,
        direct: true,
        dev,
        approximate: false,
      });
    }
  }

  // ---- transitivas: apontam para a entrada em "packages:" do lockfile ----
  const transitive = new Map<string, { pkg: PkgId; line: number; col: number; prod: boolean }>();
  const nodes = lock.graph.size ? [...lock.graph.keys()] : [...lock.packages.keys()];
  for (const id of new Set([...nodes, ...lock.packages.keys()])) {
    const pkg = parseId(id);
    if (!pkg || !/^\d/.test(pkg.version)) {
      continue;
    }
    const key = `${pkg.name}@${pkg.version}`;
    if (directKeys.has(key)) {
      continue;
    }
    const pos = lock.packages.get(id) ?? lock.packagesByKey.get(key) ?? { line: 0, col: 0 };
    const prev = transitive.get(key);
    const prod = reachable.has(id) || !!prev?.prod || (lock.devFlags.get(id) === false);
    transitive.set(key, { pkg, line: prev?.line ?? pos.line, col: prev?.col ?? pos.col, prod });
  }
  for (const t of transitive.values()) {
    const dev = lock.graph.size > 0 && !t.prod;
    if (dev && !opts.includeDev) {
      continue;
    }
    out.push({
      name: t.pkg.name,
      version: t.pkg.version,
      ecosystem: 'npm',
      manager: 'pnpm',
      projectDir: dir,
      location: lineLocation(lockPath, lines, t.line, t.col),
      spec: t.pkg.version,
      direct: false,
      dev,
      approximate: false,
    });
  }

  return { dependencies: out, members };
}

interface LockData {
  major: number;
  importers: Map<string, ImporterDep[]>;
  /** id -> posição da chave em "packages:" */
  packages: Map<string, { line: number; col: number }>;
  /** "nome@versão" -> posição (para ids com peers que só existem em "snapshots:") */
  packagesByKey: Map<string, { line: number; col: number }>;
  /** id -> [nome, ref] das dependências (snapshots no v9, packages no v5/v6) */
  graph: Map<string, [string, string][]>;
  /** id -> valor de "dev:" (v5/v6) */
  devFlags: Map<string, boolean>;
}

function readLock(text: string): LockData {
  const data: LockData = {
    major: 9,
    importers: new Map(),
    packages: new Map(),
    packagesByKey: new Map(),
    graph: new Map(),
    devFlags: new Map(),
  };
  const lines = text.split(/\r?\n/);
  let top = '';
  let importer: ImporterDep[] | undefined;
  let section: Section | undefined;
  let dep: ImporterDep | undefined;
  let node: string | undefined; // pacote atual em packages/snapshots
  let nodeDeps = false;

  // em lockfiles v5/v6 sem workspace, as seções ficam no topo (importer ".")
  const rootImporter = () => {
    if (!data.importers.has('.')) {
      data.importers.set('.', []);
    }
    return data.importers.get('.')!;
  };

  lines.forEach((line, lineNo) => {
    if (!line.trim() || line.trimStart().startsWith('#')) {
      return;
    }
    const indent = line.length - line.trimStart().length;
    const m = /^(\s*)('(?:[^']|'')*'|"[^"]*"|[^:]+?):(?:\s+(.*))?$/.exec(line);
    if (!m) {
      return;
    }
    const key = unquote(m[2]);
    const value = m[3]?.trim();

    if (indent === 0) {
      top = key;
      importer = undefined;
      section = undefined;
      dep = undefined;
      node = undefined;
      if (key === 'lockfileVersion' && value) {
        data.major = parseFloat(unquote(value)) || 9;
      }
      if ((SECTIONS as readonly string[]).includes(key)) {
        importer = rootImporter();
        section = key as Section;
      }
      return;
    }

    if (top === 'importers') {
      if (indent === 2) {
        importer = [];
        data.importers.set(key, importer);
        section = undefined;
      } else if (indent === 4) {
        section = (SECTIONS as readonly string[]).includes(key) ? (key as Section) : undefined;
      } else if (indent === 6 && importer && section) {
        dep = { name: key, section, line: lineNo, col: indent, ref: value ? unquote(value) : undefined };
        importer.push(dep);
      } else if (indent === 8 && dep && key === 'version' && value) {
        dep.ref = unquote(value);
      }
      return;
    }

    if ((SECTIONS as readonly string[]).includes(top)) {
      // v5/v6 sem workspace
      if (indent === 2 && importer && section) {
        dep = { name: key, section, line: lineNo, col: indent, ref: value ? unquote(value) : undefined };
        importer.push(dep);
      } else if (indent === 4 && dep && key === 'version' && value) {
        dep.ref = unquote(value);
      }
      return;
    }

    if (top === 'packages' || top === 'snapshots') {
      if (indent === 2) {
        node = normalizeId(key);
        nodeDeps = false;
        if (top === 'packages') {
          data.packages.set(node, { line: lineNo, col: indent });
        }
        if (top === 'snapshots' || data.major < 9) {
          if (!data.graph.has(node)) {
            data.graph.set(node, []);
          }
        }
      } else if (indent === 4 && node) {
        nodeDeps = (top === 'snapshots' || data.major < 9) && (key === 'dependencies' || key === 'optionalDependencies');
        if (key === 'dev' && value) {
          data.devFlags.set(node, value === 'true');
        }
      } else if (indent === 6 && node && nodeDeps && value) {
        data.graph.get(node)!.push([key, unquote(value)]);
      }
    }
  });

  for (const [id, pos] of data.packages) {
    const pkg = parsePkgId(id, data.major);
    if (pkg) {
      data.packagesByKey.set(`${pkg.name}@${pkg.version}`, pos);
    }
  }
  return data;
}

/** Remove a "/" inicial dos ids do v5/v6, mantendo o formato "nome@versão(peers)". */
function normalizeId(raw: string): string {
  return raw.replace(/^\//, '');
}

/**
 * Interpreta um id de pacote:
 *   v9/v6: "@babel/core@7.0.0(peer@1)"   v5: "/@babel/core/7.0.0_peer@1"
 */
function parsePkgId(raw: string, major: number): PkgId | undefined {
  const id = normalizeId(raw);
  if (major < 6) {
    const parts = id.split('/');
    const scoped = parts[0].startsWith('@');
    const name = scoped ? `${parts[0]}/${parts[1]}` : parts[0];
    const rawVersion = parts.slice(scoped ? 2 : 1).join('/');
    if (!name || !rawVersion) {
      return undefined;
    }
    return { name, version: rawVersion.split('_')[0], id: `${name}/${rawVersion}` };
  }
  const at = id.indexOf('@', 1);
  if (at < 0) {
    return undefined;
  }
  const name = id.slice(0, at);
  const rawVersion = id.slice(at + 1);
  return { name, version: rawVersion.replace(/\(.*$/, ''), id };
}

function lineLocation(file: string, lines: string[], line: number, col: number): Location {
  const l = lines[line] ?? '';
  const end = l.lastIndexOf(':');
  return { file, line, startCol: col, endCol: end > col ? end : l.length };
}

function unquote(v: string): string {
  const t = v.trim();
  if (t.startsWith("'") && t.endsWith("'")) {
    return t.slice(1, -1).replace(/''/g, "'");
  }
  if (t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1);
  }
  return t;
}
