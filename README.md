<p align="center">
  <img src="media/canary-icon2.jpg_7b2da392.jpg" alt="Canary logo: a neon-outlined canary inside a shield, with the &lt;/&gt; symbol at the top" width="280">
</p>

<h1 align="center">Canary</h1>

<p align="center">
  <em>The canary in the coal mine: an early warning when a dependency in your project has a known vulnerability.</em>
</p>

Canary is a VS Code extension that scans your workspace dependencies and flags vulnerabilities right in
the editor. It queries the public [OSV.dev](https://osv.dev) database, which is free and requires no login
or API key.

## Supported package managers

| Manager  | Files read                                           | Transitive | Workspaces |
| -------- | ---------------------------------------------------- | ---------- | ---------- |
| **npm**  | `package.json`, `package-lock.json` (v1, v2, v3)     | ✅         | ✅         |
| **pnpm** | `package.json`, `pnpm-lock.yaml` (5.x, 6.x, 9.x)     | ✅         | ✅         |
| **yarn** | `package.json`, `yarn.lock` (Classic 1.x and Berry 2+) | ✅       | ✅         |
| **uv**   | `pyproject.toml`, `uv.lock`                          | ✅         | ✅         |
| **pip**  | `requirements*.txt`                                  | —          | —          |

Python projects that follow PEP 621 without a `uv.lock` (hatch, pdm, setuptools) are also scanned from
`pyproject.toml`, with approximate versions.

## Features

- **Editor alerts:** each vulnerable dependency is underlined on the line where it is declared. The color
  depends on severity: red for critical or high, yellow for medium, blue for low. The alert shows the
  advisory ID, with a link, and the version that fixes it.
- **Quick Fix** (`Ctrl+.`):
  - changes the version in the manifest to the lowest one that fixes all known vulnerabilities of the
    package, keeping the `^` or `~` prefix it had before;
  - for uv, runs `uv lock --upgrade-package <package>` in the terminal, which also works for transitive
    dependencies;
  - opens the advisory page.
- **Side panel** (canary icon in the activity bar, on the left): vulnerable packages sorted by severity,
  with the vulnerabilities of each one.
- **Activity bar badge:** the canary icon shows how many packages have vulnerabilities; the tooltip also
  shows the total number of vulnerabilities. With no findings, the badge disappears.
- **Status bar:** total vulnerabilities, with a warning color according to the worst severity.
- **Automatic scan** when the workspace opens and whenever a manifest or lockfile changes, including after
  `npm install`, `pnpm install`, `yarn install` or `uv lock`.
- **Monorepos:** in npm, pnpm, yarn or uv workspaces, the direct dependencies of each project point to its
  own `package.json` or `pyproject.toml`, and no package is counted twice.
- **Notification with actions:** when vulnerabilities are found, a notification summarizes the findings by
  severity and offers the **Export report**, **Scan again** and **View details** buttons. On manual scans it
  always appears; on automatic ones, only when a new vulnerable package shows up.
- **Exportable report** in Markdown, CSV or JSON (see below).

## Vulnerability report

To export, use the **Export report** button in the notification, the export icon at the top of the Canary
panel, or the `Canary: Export vulnerability report` command. Choose the format and where to save; the
suggested name is `canary-report-YYYY-MM-DD.<extension>`, at the workspace root.

| Format       | Best for                          | Content                                                                                      |
| ------------ | --------------------------------- | -------------------------------------------------------------------------------------------- |
| **Markdown** | PRs, issues, documentation        | Summary by severity, package table with the recommended version, and a detailed vulnerability table |
| **CSV**      | Excel, Google Sheets, LibreOffice | One row per vulnerability, in UTF-8 with BOM (accented characters display correctly in Excel) |
| **JSON**     | CI and other tools                | Summary (totals and count by severity) and the full list of vulnerabilities                  |

Fields of each vulnerability:

| Field                         | Description                                                                                              |
| ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| Package, ecosystem, manager   | E.g. `lodash`, `npm`, `pnpm`                                                                             |
| Current version               | Installed version (or estimated when there is no lockfile, flagged as "version estimated")               |
| Fixed version                 | Lowest version that fixes **this** vulnerability                                                         |
| Recommended version           | Lowest version that fixes **all** known vulnerabilities of the package (the one the Quick Fix uses)      |
| Declared as                   | Specifier in the manifest, e.g. `^4.17.0`, `>=2.25,<3`                                                   |
| Type                          | `direct`, `dev` or `transitive`                                                                          |
| Severity                      | Critical, high, medium, low or unknown                                                                   |
| ID, CVE, aliases              | E.g. `GHSA-35jh-r3h4-6jhm`, `CVE-2021-23337`                                                             |
| Summary and publication date  | Advisory text from OSV.dev                                                                               |
| File and line                 | Where the dependency appears in the workspace                                                            |
| URL                           | Link to the advisory on `osv.dev`                                                                        |

The report is generated from the last scan and saved only on your disk; nothing is sent anywhere.

In the CSV, values starting with `=`, `+`, `-` or `@` get an apostrophe prefix (e.g. `'@babel/traverse`).
This prevents spreadsheets from interpreting external text as formulas (_CSV injection_) and avoids the
`#NAME?` error in Excel with scoped packages. In Markdown and JSON the values are left untouched.

## Commands

| Command                                  | Description                                                    |
| ---------------------------------------- | -------------------------------------------------------------- |
| `Canary: Scan for vulnerabilities`       | Scans the workspace now                                        |
| `Canary: Export vulnerability report`    | Saves the result of the last scan as Markdown, CSV or JSON     |
| `Canary: Clear results`                  | Removes the alerts and empties the panel                       |

## Settings

| Key                             | Default                                               | Description                                                                                                |
| ------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `canary.scanOnStartup`          | `true`                                                | Scan when the workspace opens                                                                              |
| `canary.scanOnChange`           | `true`                                                | Scan again when manifests or lockfiles change                                                              |
| `canary.includeDevDependencies` | `true`                                                | Include development dependencies (`devDependencies`, `[dependency-groups]`, `tool.uv.dev-dependencies`)    |
| `canary.exclude`                | `**/{node_modules,.venv,venv,.git,dist,out,build}/**` | Folders skipped when looking for manifests                                                                 |
| `canary.ignorePackages`         | `[]`                                                  | Packages that are not scanned or sent to OSV.dev (see below)                                               |

### Ignoring internal packages

Use `canary.ignorePackages` so private packages never leave your machine. Patterns accept `*` and an
optional ecosystem prefix (`npm:` or `pypi:`):

```jsonc
// .vscode/settings.json
{
  "canary.ignorePackages": [
    "@mycompany/*", // any ecosystem
    "npm:internal-*", // npm only
    "pypi:mycompany-*", // PyPI only
  ],
}
```

For Python packages, names are compared already normalized (PEP 503): `pypi:My_Company-*` also matches
`my-company-core`. Matching is case-insensitive. The **Canary** channel in the _Output_ panel shows how
many packages were ignored in each scan.

## Security and privacy

**What is sent out:** only the name, version and ecosystem of each dependency, to `https://api.osv.dev`
(maintained by Google), over HTTPS. Code, file paths and the project name are not sent. There is no
telemetry, login or other servers. Packages listed in `canary.ignorePackages` are filtered out before the
query.

**What the extension does in your environment:**

- Reads manifests and lockfiles as text or JSON; it never runs project code or invokes package managers on
  its own.
- Has no runtime dependencies: the package contains only the extension's own code.
- Only changes files when you apply a Quick Fix, and the change can be undone with `Ctrl+Z`.
- The only action that runs a command (`uv lock --upgrade-package`) only appears in trusted folders,
  validates the package name against the PyPI pattern, and requires the project folder to be inside the
  workspace.
- Fixed versions coming from OSV.dev are validated before being written to a manifest.

**Workspace Trust:** in untrusted folders (Restricted Mode), Canary keeps scanning and showing alerts,
because that is read-only, but disables the action that runs commands in the terminal.

**What Canary does not guarantee:** the absence of alerts does not mean the absence of vulnerabilities. The
extension only knows what is catalogued in OSV.dev. It warns about already-known malicious packages
(`MAL-…` IDs) but does not detect new attacks. Use it as a first line of defense, together with
`npm audit`, Dependabot and code review.

## Development

Requirements: Node.js 18 or later and VS Code 1.85 or later.

```bash
npm install
npm run compile      # or: npm run watch
```

To run the extension:

1. Open this folder in VS Code and press **F5**.
2. In the _Extension Development Host_ window, open the `sample-workspace/` folder.
3. See the alerts in the _Problems_ panel, on the canary icon and in the status bar.

Logs go to the **Canary** channel in the _Output_ panel.

Quick test without opening VS Code (reads the sample projects and queries OSV.dev for real):

```bash
npm run smoke
```

### Sample projects

The `sample-workspace/` folder has one project per package manager, all with deliberately vulnerable packages:

| Folder      | Manager          | Highlights                                                                             |
| ----------- | ---------------- | -------------------------------------------------------------------------------------- |
| `node-app/` | npm              | `lodash`, `express`; transitive `qs` and `path-to-regexp`                              |
| `pnpm-app/` | pnpm (workspace) | `axios`, `@babel/traverse` in `packages/web`; transitive `qs` forced via `overrides`   |
| `yarn-app/` | yarn (Classic)   | `lodash`, `express`; transitive `qs` and `path-to-regexp`                              |
| `uv-app/`   | uv               | `jinja2`, `flask`; transitive `urllib3` forced via `constraint-dependencies`           |
| `py-app/`   | pip              | `requests`, `django`, `urllib3`                                                        |

### Building the `.vsix` package

```bash
npm run package
code --install-extension canary-0.1.0.vsix
```

## Structure

```
src/
  extension.ts       activation, commands, alerts, Quick Fix, status bar
  tree.ts            side panel
  osv.ts             OSV.dev client (batch query and details, with cache)
  net.ts             retries for network failures and readable error messages
  parsers/npm.ts     package.json and package-lock.json
  parsers/pnpm.ts    pnpm-lock.yaml
  parsers/yarn.ts    yarn.lock (Classic and Berry)
  parsers/uv.ts      pyproject.toml and uv.lock
  parsers/python.ts  requirements*.txt and PEP 508 spec parsing
  version.ts         version comparison and extraction
  report.ts          Markdown, CSV and JSON report
  security.ts        name and version validation, canary.ignorePackages filter
  types.ts           shared types
scripts/smoke.js     quick test outside VS Code
sample-workspace/    sample projects
media/
  canary-icon.jpg    original logo (1024×1024, not included in the .vsix package)
  canary-logo.jpg    colored logo used at the top of the README
  canary-icon2.jpg   black and white logo (cropped version, not included in the .vsix package)
  icon.png           extension icon on the Marketplace (512×512, cropped from the logo)
  canary.svg         activity bar icon (monochrome stroke, 24×24)
```

The activity bar icon must be a monochrome, transparent SVG, because VS Code uses it as a mask and paints
it with the theme color. That is why it is a simplified version of the logo, without the text and without
the `</>`.

The parsers do not depend on the VS Code API and use no external libraries. They read files line by line
to keep the exact position of each dependency, which is used by the alerts and the Quick Fix.

## Troubleshooting

**"Canary: scan failed"** or **"no connection"** in the status bar

Canary needs to reach `https://api.osv.dev`. Right after VS Code opens (especially on WSL) or just after
installing the extension, the network may not be ready yet. To handle that:

- each request is retried up to 4 times, with increasing waits (about 1s, 2s and 4s), on transient failures
  (DNS, interrupted connection, timeout, HTTP 429 and 5xx);
- if an automatic scan still fails, it retries by itself after 15s, 1min and 3min;
- the results of the previous scan stay visible, and clicking the status bar forces a new scan;
- if only the details of one vulnerability fail, it appears as "Details unavailable" instead of the whole
  scan failing.

The real reason appears in the error message and in the **Canary** channel in the _Output_ panel:

| Message                                  | Likely cause                                                                                                   |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| could not resolve api.osv.dev (DNS)      | no internet, network still starting up, or WSL DNS                                                             |
| timed out / connection interrupted       | unstable or slow network                                                                                       |
| connection refused                       | firewall or proxy blocking                                                                                     |
| invalid TLS certificate                  | corporate proxy inspecting HTTPS; configure the company certificate on the system or in `NODE_EXTRA_CA_CERTS` |
| HTTP 429                                 | too many requests in a short time; wait a few moments                                                          |

## Known limitations

- **Without a lockfile**, the version is estimated from the declared range (`^4.17.0` becomes `4.17.0`);
  the alert tells you when that happens.
- **`requirements.txt`:** only `==`, `>=` and `~=` are scanned. Lines without a version, `-r` and URLs are
  ignored.
- **Transitive dependencies in npm, pnpm and yarn** have no Quick Fix. The fix is to update the package that
  pulls them in, or use `overrides` (npm, in `package.json`; pnpm, in `pnpm-workspace.yaml`) or
  `resolutions` (yarn).
- **yarn:** `yarn.lock` does not separate production from development; this is inferred from the
  `package.json` files (anything not reachable from production dependencies counts as dev). If the same
  folder has both `yarn.lock` and `package-lock.json`, only `yarn.lock` is read.
- **uv:** `uv lock --upgrade-package` only resolves when the `pyproject.toml` constraints, including
  `constraint-dependencies`, allow the fixed version.
- **Packages outside a registry** (git, URL, local path) are not queried.
- **Not supported yet:** `poetry.lock` and `Pipfile.lock`.
- Version comparison is simplified: it covers semver and the common PEP 440 cases.
- The suggested version sometimes jumps to another major version (for example Django 3.x → 4.2.x) when the
  current series did not receive a fix.

## Next steps

- Support for `poetry.lock`, `Pipfile.lock`, `go.mod`, `pom.xml` and `Cargo.lock`.
- Quick Fix with `overrides` for npm and pnpm transitive dependencies.
- Persistent cache to work offline.
- Show the dependency chain of transitive packages (which package brings them in).
- SARIF report (for GitHub Code Scanning) and a CLI mode for CI.

## License

[MIT](LICENSE.md) © 2026 eduardo239
