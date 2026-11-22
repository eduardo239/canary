export type Ecosystem = 'npm' | 'PyPI';

/** Tool that manages the dependency (defines how to fix it). */
export type Manager = 'npm' | 'pnpm' | 'yarn' | 'pip' | 'uv';

export type Severity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN';

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/** Position (0-based) of a span inside a file. */
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
  /** Project folder (where to run commands such as "uv lock"). */
  projectDir?: string;
  /** Where the dependency appears (package.json, package-lock.json, requirements.txt...). */
  location: Location;
  /** Exact span of the version in the file, when editable (used by the Quick Fix). */
  versionLocation?: Location;
  /** Original specifier, e.g. "^4.17.0" or "==2.19.0". */
  spec: string;
  direct: boolean;
  dev: boolean;
  /** true when the version was inferred from a range (no lockfile). */
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

/** Result of a lockfile project parser. */
export interface ParseResult {
  dependencies: Dependency[];
  /** Workspace member folders already covered by this lockfile. */
  members: string[];
}
