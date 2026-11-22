import { normalizePyName } from './parsers/python';
import { Dependency } from './types';

/** Valid PyPI name (PEP 508): letters, digits, ".", "_" and "-", starting and ending with a letter or digit. */
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

/**
 * Validates a package name before using it in a terminal command.
 * Names come from workspace files, which may have been tampered with.
 */
export function isSafePyPackageName(name: string): boolean {
  return name.length <= 200 && PYPI_NAME.test(name);
}

/** Version made of characters that are safe to write into a manifest (e.g. "4.17.21", "2.0.0-rc.1", "1.0.post1"). */
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$/;

export function isSafeVersion(version: string): boolean {
  return VERSION.test(version);
}

/**
 * Compiles the canary.ignorePackages patterns.
 *   "@company/*"        any ecosystem
 *   "npm:@company/*"    npm only
 *   "pypi:company-*"    PyPI only (names are compared normalized, PEP 503)
 * "*" matches any sequence of characters; matching is case-insensitive.
 */
export function compileIgnorePatterns(patterns: readonly string[]): (dep: Pick<Dependency, 'name' | 'ecosystem'>) => boolean {
  const rules = patterns
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const m = /^(npm|pypi):(.*)$/i.exec(p);
      const ecosystem = m ? (m[1].toLowerCase() === 'npm' ? 'npm' : 'PyPI') : undefined;
      const glob = m ? m[2] : p;
      const toRegex = (g: string) =>
        new RegExp(
          `^${g
            .split('*')
            .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
            .join('.*')}$`,
          'i',
        );
      // for PyPI the pattern is normalized too (PEP 503): "My_Company-*" == "my-company-*"
      return { ecosystem, re: toRegex(glob), rePy: toRegex(normalizePyName(glob)) };
    });
  if (!rules.length) {
    return () => false;
  }
  return (dep) =>
    rules.some((r) => {
      if (r.ecosystem && r.ecosystem !== dep.ecosystem) {
        return false;
      }
      return dep.ecosystem === 'PyPI' ? r.rePy.test(normalizePyName(dep.name)) : r.re.test(dep.name);
    });
}
