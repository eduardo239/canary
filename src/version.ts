/**
 * Simplified version comparison (enough for semver and most PEP 440 versions).
 * Compares numeric segments; a version with a pre-release suffix is lower than the final version.
 */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const clean = v.trim().replace(/^v/i, '').split('+')[0];
    const m = /^([0-9]+(?:\.[0-9]+)*)(.*)$/.exec(clean);
    if (!m) {
      return { nums: [] as number[], pre: clean };
    }
    return { nums: m[1].split('.').map(Number), pre: m[2].replace(/^[-.]/, '') };
  };
  const pa = parse(a);
  const pb = parse(b);
  const len = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  if (pa.pre === pb.pre) {
    return 0;
  }
  if (!pa.pre) {
    return 1;
  }
  if (!pb.pre) {
    return -1;
  }
  return pa.pre < pb.pre ? -1 : 1;
}

/** Extracts a concrete version from a spec ("^1.2.3" -> "1.2.3", "~1.2" -> "1.2.0"). */
export function versionFromSpec(spec: string): string | undefined {
  const s = spec.trim();
  if (!s || /^(file:|link:|git|github:|http|workspace:|npm:|\*|latest|x$)/i.test(s)) {
    return undefined;
  }
  const full = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/.exec(s);
  if (full) {
    return full[1];
  }
  const partial = /(\d+)(?:\.(\d+))?/.exec(s);
  if (partial) {
    return `${partial[1]}.${partial[2] ?? '0'}.0`;
  }
  return undefined;
}
