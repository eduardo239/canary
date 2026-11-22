import * as fs from 'fs/promises';
import * as path from 'path';
import { Dependency, Location, ParseResult } from '../types';
import { versionFromSpec } from '../version';

const DEP_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;

export interface NpmOptions {
  includeDev: boolean;
}

export async function readOptional(file: string): Promise<string | undefined> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}

/**
 * Reads an npm project (folder with package.json and/or package-lock.json).
 * With a lockfile: uses exact versions, including transitive dependencies.
 * Without a lockfile: uses the package.json ranges (approximate versions).
 */
export async function parseNpmProject(dir: string, opts: NpmOptions): Promise<ParseResult> {
  const pkgPath = path.join(dir, 'package.json');
  const lockPath = path.join(dir, 'package-lock.json');
  const [pkgText, lockText] = await Promise.all([readOptional(pkgPath), readOptional(lockPath)]);

  const manifest = pkgText ? new ManifestIndex(pkgPath, pkgText) : undefined;

  if (lockText) {
    try {
      return parseLockfile(dir, lockPath, lockText, manifest, opts);
    } catch {
      // invalid lockfile: fall back to package.json
    }
  }
  return { dependencies: manifest ? manifest.dependencies(opts) : [], members: [] };
}

/** package.json index with the line of each declared dependency. */
export class ManifestIndex {
  private readonly json: any;
  private readonly lines: string[];
  /** name -> { section, spec, location } */
  readonly declared = new Map<string, { section: string; spec: string; location: Location; versionLocation?: Location }>();

  constructor(readonly file: string, text: string) {
    this.json = JSON.parse(text);
    this.lines = text.split(/\r?\n/);
    for (const section of DEP_SECTIONS) {
      const deps = this.json[section];
      if (!deps || typeof deps !== 'object') {
        continue;
      }
      const sectionLine = this.lines.findIndex((l) => new RegExp(`^\\s*"${section}"\\s*:`).test(l));
      for (const [name, spec] of Object.entries<string>(deps)) {
        if (this.declared.has(name) || typeof spec !== 'string') {
          continue;
        }
        this.declared.set(name, { section, spec, ...this.locate(name, spec, Math.max(sectionLine, 0)) });
      }
    }
  }

  private locate(name: string, spec: string, fromLine: number): { location: Location; versionLocation?: Location } {
    const keyRe = new RegExp(`^(\\s*)"${escapeRe(name)}"\\s*:`);
    let line = -1;
    for (let i = fromLine; i < this.lines.length; i++) {
      if (keyRe.test(this.lines[i])) {
        line = i;
        break;
      }
    }
    if (line < 0) {
      return { location: { file: this.file, line: 0, startCol: 0, endCol: 1 } };
    }
    const text = this.lines[line];
    const keyStart = text.indexOf('"');
    const location: Location = { file: this.file, line, startCol: keyStart, endCol: keyStart + name.length + 2 };
    const colon = text.indexOf(':', location.endCol);
    const specStart = text.indexOf(`"${spec}"`, colon);
    const versionLocation =
      specStart >= 0 ? { file: this.file, line, startCol: specStart + 1, endCol: specStart + 1 + spec.length } : undefined;
    return { location, versionLocation };
  }

  dependencies(opts: NpmOptions): Dependency[] {
    const out: Dependency[] = [];
    for (const [name, d] of this.declared) {
      const dev = d.section === 'devDependencies';
      if ((dev && !opts.includeDev) || d.section === 'peerDependencies') {
        continue;
      }
      const version = versionFromSpec(d.spec);
      if (!version) {
        continue;
      }
      out.push({
        name,
        version,
        ecosystem: 'npm',
      manager: 'npm',
        location: d.location,
        versionLocation: d.versionLocation,
        spec: d.spec,
        direct: true,
        dev,
        approximate: version !== d.spec.trim(),
      });
    }
    return out;
  }
}

function parseLockfile(
  dir: string,
  lockPath: string,
  lockText: string,
  manifest: ManifestIndex | undefined,
  opts: NpmOptions,
): ParseResult {
  const lock = JSON.parse(lockText);
  const lines = lockText.split(/\r?\n/);
  const out: Dependency[] = [];
  const members: string[] = [];

  const lockLocation = (line: number): Location => {
    const text = lines[line] ?? '';
    const start = Math.max(text.indexOf('"'), 0);
    const end = text.indexOf('"', start + 1);
    return { file: lockPath, line, startCol: start, endCol: end > start ? end + 1 : text.length };
  };

  const push = (keyName: string, entry: any, line: number, isTopLevel: boolean) => {
    if (!entry || entry.link || typeof entry.version !== 'string') {
      return;
    }
    if (entry.dev && !opts.includeDev) {
      return;
    }
    const version = entry.version;
    if (!/^\d/.test(version)) {
      return; // git/url/file
    }
    const declared = isTopLevel ? manifest?.declared.get(keyName) : undefined;
    out.push({
      name: entry.name ?? keyName,
      version,
      ecosystem: 'npm',
      manager: 'npm',
      location: declared ? declared.location : lockLocation(line),
      versionLocation: declared?.versionLocation,
      spec: declared?.spec ?? version,
      direct: !!declared,
      dev: !!entry.dev,
      approximate: false,
    });
  };

  if (lock.packages && typeof lock.packages === 'object') {
    // lockfileVersion 2 and 3
    const keyLines = new Map<string, number>();
    lines.forEach((l, i) => {
      const m = /^\s*"((?:[^"]*\/)?node_modules\/[^"]+)"\s*:\s*\{/.exec(l);
      if (m && !keyLines.has(m[1])) {
        keyLines.set(m[1], i);
      }
    });
    for (const [key, entry] of Object.entries<any>(lock.packages)) {
      const idx = key.lastIndexOf('node_modules/');
      if (idx < 0) {
        if (key) {
          members.push(path.join(dir, key)); // workspace package
        }
        continue;
      }
      const keyName = key.slice(idx + 'node_modules/'.length);
      push(keyName, entry, keyLines.get(key) ?? 0, key === `node_modules/${keyName}`);
    }
  } else if (lock.dependencies && typeof lock.dependencies === 'object') {
    // lockfileVersion 1 (recursive tree)
    const firstLine = (name: string) => {
      const re = new RegExp(`^\\s*"${escapeRe(name)}"\\s*:\\s*\\{`);
      return Math.max(lines.findIndex((l) => re.test(l)), 0);
    };
    const walk = (deps: Record<string, any>, depth: number) => {
      for (const [name, entry] of Object.entries(deps)) {
        push(name, entry, firstLine(name), depth === 0);
        if (entry?.dependencies) {
          walk(entry.dependencies, depth + 1);
        }
      }
    };
    walk(lock.dependencies, 0);
  }
  return { dependencies: out, members };
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
