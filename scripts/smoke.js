// Teste rápido fora do VS Code: parsers + consulta real à OSV.dev.
const path = require('path');
const { parseNpmProject } = require('../out/parsers/npm');
const { parseRequirements } = require('../out/parsers/python');
const { parseUvProject } = require('../out/parsers/uv');
const { OsvClient } = require('../out/osv');

(async () => {
  const root = path.resolve(process.argv[2] || path.join(__dirname, '..', 'sample-workspace'));
  const deps = [
    ...(await parseNpmProject(path.join(root, 'node-app'), { includeDev: true })),
    ...(await parseRequirements(path.join(root, 'py-app', 'requirements.txt'))),
    ...(await parseUvProject(path.join(root, 'uv-app'), { includeDev: true })),
  ];
  console.log('Dependências:');
  for (const d of deps) {
    const rel = path.relative(root, d.location.file);
    const fix = d.versionLocation ? ` [versão editável: col ${d.versionLocation.startCol}-${d.versionLocation.endCol}]` : '';
    console.log(`  ${d.manager.padEnd(3)} ${`${d.name}@${d.version}`.padEnd(30)} ${d.direct ? (d.dev ? 'dev       ' : 'direta    ') : 'transitiva'} ${rel}:${d.location.line + 1}${d.approximate ? ' (aprox.)' : ''}${fix}`);
  }
  const findings = await new OsvClient().scan(deps);
  console.log('\nAchados:');
  for (const f of findings) {
    console.log(`  [${f.dependency.manager}] ${f.dependency.name}@${f.dependency.version}: ${f.vulnerabilities.length} vulnerabilidade(s)`);
    for (const v of f.vulnerabilities.slice(0, 2)) {
      console.log(`     - ${v.id} [${v.severity}] fix=${v.fixedVersion ?? '-'} ${v.summary.slice(0, 64)}`);
    }
  }
})().catch((e) => { console.error(e); process.exit(1); });
