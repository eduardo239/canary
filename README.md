# Ext Scan – Vulnerabilidades em Dependências

Extensão para VS Code que analisa as dependências do workspace e aponta vulnerabilidades conhecidas,
usando a base pública [OSV.dev](https://osv.dev) (gratuita, sem login nem chave de API).

## Recursos

- **Ecossistemas:**
  - npm: `package.json` + `package-lock.json` (v1/v2/v3)
  - uv: `pyproject.toml` + `uv.lock`, incluindo workspaces, extras e `[dependency-groups]`
  - pip: `requirements*.txt`
  - Projetos PEP 621 sem `uv.lock` (hatch, pdm, setuptools...) também são lidos pelo `pyproject.toml`, com versões aproximadas.
- **Dependências transitivas:** lidas do `package-lock.json` e do `uv.lock`.
- **Diagnostics no editor:** sublinhado na linha da dependência, com severidade, ID do advisory (link clicável) e versão corrigida.
- **Quick Fix** (`Ctrl+.`):
  - atualiza a versão no manifesto para a menor que corrige todas as vulnerabilidades conhecidas do pacote;
  - no uv, roda `uv lock --upgrade-package <pacote>` no terminal (funciona também para transitivas);
  - abre o advisory.
- **Painel lateral** (ícone de escudo): pacotes vulneráveis ordenados por severidade.
- **Status bar** com o total de vulnerabilidades.
- **Verificação automática** ao abrir o workspace e quando um manifesto muda (inclusive depois de `npm install`).

## Como rodar em desenvolvimento

```bash
npm install
npm run compile
```

Abra esta pasta no VS Code e pressione **F5**. Na janela *Extension Development Host*, abra a pasta
`sample-workspace/` (que tem pacotes vulneráveis de propósito) e veja os resultados.

Teste rápido sem abrir o VS Code (parsers + consulta real à OSV):

```bash
npm run smoke
```

## Gerar o .vsix para instalar

```bash
npm run package
code --install-extension ext-scan-0.1.0.vsix
```

## Configurações

| Chave | Padrão | Descrição |
|---|---|---|
| `extScan.scanOnStartup` | `true` | Verifica ao abrir o workspace |
| `extScan.scanOnChange` | `true` | Verifica de novo quando os manifestos mudam |
| `extScan.includeDevDependencies` | `true` | Inclui dependências de dev (`devDependencies`, `[dependency-groups]`, `tool.uv.dev-dependencies`) |
| `extScan.exclude` | `**/{node_modules,.venv,venv,.git,dist,out,build}/**` | Pastas ignoradas |

## Limitações conhecidas (MVP)

- Sem lockfile, a versão é **estimada** pela faixa (`^4.17.0` vira `4.17.0`); o diagnostic avisa quando isso acontece.
- Em `requirements.txt`, só `==`, `>=` e `~=` são analisados; linhas sem versão, `-r` e URLs são ignoradas.
- Vulnerabilidades transitivas do npm aparecem no `package-lock.json`, sem Quick Fix. A correção é atualizar o pacote pai ou usar `overrides`.
- No uv, `uv lock --upgrade-package` só resolve se as restrições do `pyproject.toml` (inclusive `constraint-dependencies`) permitirem a versão corrigida.
- Só pacotes vindos de registry (PyPI) são consultados; dependências git, URL ou caminho local são ignoradas.
- `[tool.poetry.dependencies]` e `poetry.lock` ainda não são suportados.
- A comparação de versões é simplificada (cobre semver e os casos comuns do PEP 440).

## Estrutura

```
src/
  extension.ts      ativação, comandos, diagnostics, quick fix, status bar
  tree.ts           painel lateral
  osv.ts            cliente OSV.dev (querybatch + detalhes, com cache)
  parsers/npm.ts    package.json / package-lock.json
  parsers/python.ts requirements*.txt e leitura de specs PEP 508
  parsers/uv.ts     pyproject.toml / uv.lock
  version.ts        comparação e extração de versões
  types.ts
```

## Próximos passos sugeridos

- Mais ecossistemas: `poetry.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `pom.xml`, `Cargo.lock`.
- Cache persistente (`context.globalState`) para funcionar offline.
- Mostrar a cadeia de dependência das transitivas (quem puxa o pacote).
- Exportar um relatório (JSON/SARIF) e um modo CLI para CI.
