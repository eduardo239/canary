export type Ecosystem = 'npm' | 'PyPI';

/** Ferramenta que gerencia a dependência (define como corrigir). */
export type Manager = 'npm' | 'pnpm' | 'pip' | 'uv';

export type Severity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN';

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/** Posição (0-based) de um trecho dentro de um arquivo. */
export interface Location {
  file: string;
  line: number;
  startCol: number;
  endCol: number;
}

export interface Dependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  manager: Manager;
  /** Pasta do projeto (onde rodar comandos como "uv lock"). */
  projectDir?: string;
  /** Onde a dependência aparece (package.json, package-lock.json ou requirements.txt). */
  location: Location;
  /** Trecho exato da versão no arquivo, quando editável (usado pelo Quick Fix). */
  versionLocation?: Location;
  /** Especificação original, ex.: "^4.17.0" ou "==2.19.0". */
  spec: string;
  direct: boolean;
  dev: boolean;
  /** true quando a versão foi deduzida de uma faixa (sem lockfile). */
  approximate: boolean;
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  fixedVersion?: string;
  url: string;
  published?: string;
}

export interface Finding {
  dependency: Dependency;
  vulnerabilities: Vulnerability[];
}

/** Resultado de um parser de projeto com lockfile. */
export interface ParseResult {
  dependencies: Dependency[];
  /** Pastas de membros de workspace já cobertas por este lockfile. */
  members: string[];
}
