import * as fs from 'fs/promises';
import * as path from 'path';
import { Dependency, Location, ParseResult } from '../types';
import { ManifestIndex, readOptional } from './npm';

export interface YarnOptions {
  includeDev: boolean;
}

interface Node {
  name: string;
  version: string;
  /** [name, range] of dependencies and optionalDependencies */
  deps: [string, string][];
  line: number;
  endCol: number;
}

interface LockData {
  /** "name@range" (as it appears in the lockfile key) -> id "name@version" */
  descriptors: Map<string, string>;
  nodes: Map<string, Node>;
  /** relative workspace folders listed in the lockfile (Yarn 2+) */
  workspaces: string[];
}

/**
 * Yarn project: yarn.lock (Classic 1.x and Berry 2+) + the root and workspace package.json files.
 * yarn.lock does not distinguish production from development; that comes from the package.json files:
 * anything not reachable from production dependencies is flagged as dev.
 */
export async function parseYarnProject(dir: string, opts: YarnOptions): Promise<ParseResult> {
  const lockPath = path.join(dir, 'yarn.lock');
  const text = await readOptional(lockPath);
  if (!text) {
    return { dependencies: [], members: [] };
  }
  const lock = readLock(text);

  // ---- projects: the root and each workspace ----
  const rootManifest = await loadManifest(path.join(dir, 'package.json'));
  const memberDirs = new Set<string>();
  for (const rel of lock.workspaces) {
    if (rel !== '.') {
      memberDirs.add(path.join(dir, rel));
    }
  }
  for (const d of await expandWorkspaces(dir, rootManifest?.workspaces ?? [])) {
    memberDirs.add(d);
  }
  const projects: { dir: string; manifest?: ManifestIndex }[] = [{ dir, manifest: rootManifest?.index }];
  for (const d of memberDirs) {
    projects.push({ dir: d, manifest: (await loadManifest(path.join(d, 'package.json')))?.index });
  }

  const find = (name: string, range: string): string | undefined => {
    for (const key of [`${name}@${range}`, `${name}@npm:${range}`]) {
      const id = lock.descriptors.get(key);
      if (id) {
        return id;
      }
    }
    // Yarn 2+: "patch:resolve@npm%3A^1.1.7#..." points to the original descriptor
    const patch = /^patch:(.+?)(?:#|$)/.exec(range);
    return patch ? lock.descriptors.get(safeDecode(patch[1])) : undefined;
  };

  // ---- what is reachable from production dependencies (to flag dev) ----
  const roots: string[] = [];
  for (const p of projects) {
    for (const [name, d] of p.manifest?.declared ?? []) {
      const id = d.section === 'dependencies' || d.section === 'optionalDependencies' ? find(name, d.spec) : undefined;
      if (id) {
        roots.push(id);
      }
    }
  }
  const reachable = new Set<string>();
  const stack = [...roots];
  while (stack.length) {
    const id = stack.pop()!;
    if (reachable.has(id)) {
      continue;
    }
    reachable.add(id);
    for (const [name, range] of lock.nodes.get(id)?.deps ?? []) {
      const child = find(name, range);
      if (child && !reachable.has(child)) {
        stack.push(child);
      }
    }
  }

  // ---- direct dependencies: point to each project's package.json ----
  const out: Dependency[] = [];
  const directKeys = new Set<string>();
  for (const p of projects) {
    for (const [name, d] of p.manifest?.declared ?? []) {
      if (d.section === 'peerDependencies') {
        continue;
      }
      const id = find(name, d.spec);
      const node = id ? lock.nodes.get(id) : undefined;
      if (!node || !/^\d/.test(node.version)) {
        continue;
      }
      directKeys.add(`${node.name}@${node.version}`);
      const dev = d.section === 'devDependencies';
      if (dev && !opts.includeDev) {
        continue;
      }
      out.push({
        name: node.name,
        version: node.version,
        ecosystem: 'npm',
        manager: 'yarn',
        projectDir: p.dir,
        location: d.location,
        // ranges with a protocol (npm:alias@^1, patch:...) are not edited by the Quick Fix
        versionLocation: /^[a-z]+:/i.test(d.spec) ? undefined : d.versionLocation,
        spec: d.spec,
        direct: true,
        dev,
        approximate: false,
      });
    }
  }

  // ---- transitive: point to the entry in yarn.lock ----
  const hasRoots = roots.length > 0;
  for (const [id, node] of lock.nodes) {
    if (!/^\d/.test(node.version) || directKeys.has(id)) {
      continue;
    }
    const dev = hasRoots && !reachable.has(id);
    if (dev && !opts.includeDev) {
      continue;
    }
    const location: Location = { file: lockPath, line: node.line, startCol: 0, endCol: node.endCol };
    out.push({
      name: node.name,
      version: node.version,
      ecosystem: 'npm',
      manager: 'yarn',
      projectDir: dir,
      location,
      spec: node.version,
      direct: false,
      dev,
      approximate: false,
    });
  }

  return { dependencies: out, members: [...memberDirs] };
}

const NON_REGISTRY = /^(git|github|gitlab|bitbucket|file|link|portal|exec|workspace|http|https)[:+]|^git\+/;

function readLock(text: string): LockData {
  const data: LockData = { descriptors: new Map(), nodes: new Map(), workspaces: [] };
  interface Raw {
    descriptors: string[];
    version?: string;
    resolution?: string;
    deps: [string, string][];
    line: number;
    endCol: number;
  }
  const raws: Raw[] = [];
  let berry = false;
  let cur: Raw | undefined;
  let section = false;

  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim() || line.trimStart().startsWith('#')) {
      return;
    }
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      section = false;
      const key = line.replace(/:\s*$/, '');
      if (key === '__metadata') {
        berry = true;
        cur = undefined;
        return;
      }
      // Classic: "a@^1", "a@^2":   Berry: "a@npm:^1, a@npm:^2":
      const descriptors = key.replace(/"/g, '').split(',').map((s) => s.trim()).filter(Boolean);
      cur = { descriptors, deps: [], line: i, endCol: key.length };
      raws.push(cur);
      return;
    }
    if (!cur) {
      return;
    }
    if (indent === 2) {
      const m = /^\s{2}([A-Za-z]+):?(?:\s+(.*))?$/.exec(line);
      section = false;
      if (!m) {
        return;
      }
      const value = unquote(m[2] ?? '');
      if (m[1] === 'version') {
        cur.version = value;
      } else if (m[1] === 'resolution') {
        cur.resolution = value;
      } else if ((m[1] === 'dependencies' || m[1] === 'optionalDependencies') && !value) {
        section = true;
      }
    } else if (indent === 4 && section) {
      const m = /^\s{4}("[^"]+"|[^\s:]+):?\s+(.+)$/.exec(line);
      if (m) {
        cur.deps.push([unquote(m[1]), unquote(m[2])]);
      }
    }
  });

  for (const raw of raws) {
    let name: string | undefined;
    if (berry) {
      const res = raw.resolution;
      const at = res ? res.indexOf('@', 1) : -1;
      if (!res || at < 0) {
        continue;
      }
      const protocol = res.slice(at + 1);
      if (protocol.startsWith('workspace:')) {
        data.workspaces.push(protocol.slice('workspace:'.length));
        continue;
      }
      if (!protocol.startsWith('npm:')) {
        continue; // patch:, git, portal...
      }
      name = res.slice(0, at);
    } else {
      const first = raw.descriptors[0] ?? '';
      const at = first.indexOf('@', 1);
      if (at < 0) {
        continue;
      }
      name = first.slice(0, at);
      const range = first.slice(at + 1);
      if (NON_REGISTRY.test(range)) {
        continue;
      }
      if (range.startsWith('npm:')) {
        // alias: "nickname@npm:real-package@^1"
        const inner = range.slice(4);
        const innerAt = inner.indexOf('@', 1);
        if (innerAt > 0) {
          name = inner.slice(0, innerAt);
        }
      }
    }
    if (!raw.version) {
      continue;
    }
    const id = `${name}@${raw.version}`;
    for (const d of raw.descriptors) {
      data.descriptors.set(d, id);
    }
    const existing = data.nodes.get(id);
    if (existing) {
      existing.deps.push(...raw.deps);
    } else {
      data.nodes.set(id, { name, version: raw.version, deps: [...raw.deps], line: raw.line, endCol: raw.endCol });
    }
  }
  return data;
}

async function loadManifest(file: string): Promise<{ index: ManifestIndex; workspaces: string[] } | undefined> {
  const text = await readOptional(file);
  if (!text) {
    return undefined;
  }
  try {
    const json = JSON.parse(text);
    const ws = Array.isArray(json.workspaces) ? json.workspaces : json.workspaces?.packages;
    return {
      index: new ManifestIndex(file, text),
      workspaces: Array.isArray(ws) ? ws.filter((w: unknown): w is string => typeof w === 'string') : [],
    };
  } catch {
    return undefined;
  }
}

/** Expands the "workspaces" patterns (supports "*" and "**") into folders that have a package.json. */
async function expandWorkspaces(root: string, patterns: string[]): Promise<string[]> {
  const found = new Set<string>();
  for (const pattern of patterns) {
    if (pattern.startsWith('!')) {
      continue;
    }
    const segments = pattern.replace(/^\.\//, '').split('/').filter(Boolean);
    for (const d of await expand(root, segments)) {
      if (d !== root && (await readOptional(path.join(d, 'package.json'))) !== undefined) {
        found.add(d);
      }
    }
  }
  return [...found];
}

async function expand(base: string, segments: string[]): Promise<string[]> {
  if (!segments.length) {
    return [base];
  }
  const [head, ...rest] = segments;
  if (head === '**') {
    const out = await expand(base, rest);
    for (const sub of await subdirs(base)) {
      out.push(...(await expand(path.join(base, sub), segments)));
    }
    return out;
  }
  if (head.includes('*')) {
    const re = new RegExp(`^${head.split('*').map(escapeRe).join('[^/]*')}$`);
    const out: string[] = [];
    for (const sub of await subdirs(base)) {
      if (re.test(sub)) {
        out.push(...(await expand(path.join(base, sub), rest)));
      }
    }
    return out;
  }
  return expand(path.join(base, head), rest);
}

async function subdirs(dir: string): Promise<string[]> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory() && e.name !== 'node_modules' && !e.name.startsWith('.')).map((e) => e.name);
  } catch {
    return [];
  }
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function unquote(v: string): string {
  const t = v.trim();
  return t.length >= 2 && t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
}
