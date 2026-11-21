import { normalizePyName } from './parsers/python';
import { Dependency } from './types';

/** Nome válido no PyPI (PEP 508): letras, dígitos, ".", "_" e "-", começando e terminando com letra ou dígito. */
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

/**
 * Valida um nome de pacote antes de usá-lo num comando de terminal.
 * Os nomes vêm de arquivos do workspace, que podem ter sido manipulados.
 */
export function isSafePyPackageName(name: string): boolean {
  return name.length <= 200 && PYPI_NAME.test(name);
}

/** Versão com caracteres seguros para escrever num manifesto (ex.: "4.17.21", "2.0.0-rc.1", "1.0.post1"). */
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$/;

export function isSafeVersion(version: string): boolean {
  return VERSION.test(version);
}

/**
 * Compila os padrões de canary.ignorePackages.
 *   "@empresa/*"        qualquer ecossistema
 *   "npm:@empresa/*"    só npm
 *   "pypi:empresa-*"    só PyPI (nomes comparados já normalizados, PEP 503)
 * "*" casa com qualquer sequência de caracteres; a comparação ignora maiúsculas.
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
      // para PyPI, o padrão também é normalizado (PEP 503): "Minha_Empresa-*" == "minha-empresa-*"
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
