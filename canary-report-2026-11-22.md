# Relatório de vulnerabilidades — Canary

- **Workspace:** canary9 [WSL: Ubuntu]
- **Gerado em:** 2026-11-22 10:40
- **Dependências analisadas:** 111
- **Pacotes vulneráveis:** 19
- **Vulnerabilidades:** 124
- **Fonte:** [OSV.dev](https://osv.dev)

## Resumo por severidade

| Severidade | Quantidade |
|---|---:|
| Crítica | 8 |
| Alta | 50 |
| Média | 56 |
| Baixa | 10 |

## Pacotes e correções recomendadas

| Pacote | Versão atual | Atualizar para | Pior severidade | Vulnerabilidades | Tipo | Local |
|---|---|---|---|---:|---|---|
| `@babel/traverse` (pnpm) | 7.22.0 | **7.23.2** | Crítica | 1 | direta | `sample-workspace/pnpm-app/packages/web/package.json:6` |
| `django` (pip) | 3.0.0 ⚠️ estimada | **5.2.17** | Crítica | 28 | direta | `sample-workspace/py-app/requirements.txt:3` |
| `minimist` (pnpm) | 1.2.5 | **1.2.6** | Crítica | 1 | dev | `sample-workspace/pnpm-app/package.json:9` |
| `minimist` (npm) | 1.2.5 | **1.2.6** | Crítica | 1 | dev | `sample-workspace/node-app/package.json:9` |
| `minimist` (npm) | 1.2.5 | **1.2.6** | Crítica | 1 | dev | `sample-workspace/yarn-app/package.json:9` |
| `axios` (pnpm) | 0.21.0 | **0.33.0** | Alta | 25 | direta | `sample-workspace/pnpm-app/packages/web/package.json:5` |
| `flask` (uv) | 2.2.0 | **3.1.3** | Alta | 2 | direta | `sample-workspace/uv-app/pyproject.toml:12` |
| `lodash` (pnpm) | 4.17.15 | **4.18.0** | Alta | 5 | direta | `sample-workspace/pnpm-app/package.json:5` |
| `lodash` (npm) | 4.17.15 | **4.18.0** | Alta | 5 | direta | `sample-workspace/node-app/package.json:5` |
| `lodash` (npm) | 4.17.15 | **4.18.0** | Alta | 5 | direta | `sample-workspace/yarn-app/package.json:5` |
| `path-to-regexp` (npm) | 0.1.7 | **0.1.13** | Alta | 2 | transitiva | `sample-workspace/node-app/package-lock.json:26` |
| `qs` (pnpm) | 6.7.0 | **6.16.1** | Alta | 5 | transitiva | `sample-workspace/pnpm-app/pnpm-lock.yaml:284` |
| `qs` (npm) | 6.7.0 | **6.16.1** | Alta | 5 | transitiva | `sample-workspace/node-app/package-lock.json:23` |
| `requests` (pip) | 2.19.0 | **2.33.0** | Alta | 5 | direta | `sample-workspace/py-app/requirements.txt:2` |
| `urllib3` (uv) | 1.26.4 | **2.8.0** | Alta | 11 | transitiva | `sample-workspace/uv-app/uv.lock:631` |
| `urllib3` (pip) | 1.24.1 | **2.8.0** | Alta | 13 | direta | `sample-workspace/py-app/requirements.txt:5` |
| `express` (npm) | 4.17.1 | **4.20.0** | Média | 2 | direta | `sample-workspace/node-app/package.json:6` |
| `express` (npm) | 4.17.1 ⚠️ estimada | **4.20.0** | Média | 2 | direta | `sample-workspace/yarn-app/package.json:6` |
| `jinja2` (uv) | 3.1.2 | **3.1.6** | Média | 5 | direta | `sample-workspace/uv-app/pyproject.toml:7` |

## Vulnerabilidades

| Severidade | ID | CVE | Pacote | Versão atual | Corrigida em | Resumo |
|---|---|---|---|---|---|---|
| Crítica | [GHSA-67hx-6x53-jw92](https://osv.dev/vulnerability/GHSA-67hx-6x53-jw92) | CVE-2023-45133 | `@babel/traverse` | 7.22.0 | 7.23.2 | Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code |
| Crítica | [GHSA-frmv-pr5f-9mcr](https://osv.dev/vulnerability/GHSA-frmv-pr5f-9mcr) | CVE-2025-64459 | `django` | 3.0.0 | 4.2.26 | Django vulnerable to SQL injection via _connector keyword argument in QuerySet and Q objects. |
| Crítica | [GHSA-hmr4-m2h5-33qx](https://osv.dev/vulnerability/GHSA-hmr4-m2h5-33qx) | CVE-2020-7471 | `django` | 3.0.0 | 3.0.3 | SQL injection in Django |
| Crítica | [GHSA-vfq6-hq5r-27r6](https://osv.dev/vulnerability/GHSA-vfq6-hq5r-27r6) | CVE-2019-19844 | `django` | 3.0.0 | 3.0.1 | Django Potential account hijack via password reset form |
| Crítica | [GHSA-xpfp-f569-q3p2](https://osv.dev/vulnerability/GHSA-xpfp-f569-q3p2) | CVE-2021-35042 | `django` | 3.0.0 | 3.1.13 | SQL Injection in Django |
| Crítica | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | `minimist` | 1.2.5 | 1.2.6 | Prototype Pollution in minimist |
| Crítica | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | `minimist` | 1.2.5 | 1.2.6 | Prototype Pollution in minimist |
| Crítica | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | `minimist` | 1.2.5 | 1.2.6 | Prototype Pollution in minimist |
| Alta | [GHSA-3g43-6gmg-66jw](https://osv.dev/vulnerability/GHSA-3g43-6gmg-66jw) | CVE-2026-44495 | `axios` | 0.21.0 | 0.31.1 | axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge |
| Alta | [GHSA-43fc-jf86-j433](https://osv.dev/vulnerability/GHSA-43fc-jf86-j433) | CVE-2026-25639 | `axios` | 0.21.0 | 0.30.3 | Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig |
| Alta | [GHSA-6chq-wfr3-2hj9](https://osv.dev/vulnerability/GHSA-6chq-wfr3-2hj9) | CVE-2026-42035 | `axios` | 0.21.0 | 0.31.1 | Axios: Header Injection via Prototype Pollution |
| Alta | [GHSA-cph5-m8f7-6c5x](https://osv.dev/vulnerability/GHSA-cph5-m8f7-6c5x) | CVE-2021-3749 | `axios` | 0.21.0 | 0.21.2 | axios Inefficient Regular Expression Complexity vulnerability |
| Alta | [GHSA-hfxv-24rg-xrqf](https://osv.dev/vulnerability/GHSA-hfxv-24rg-xrqf) | CVE-2026-44496 | `axios` | 0.21.0 | 0.32.0 | Axios: Regular Expression Denial of Service (ReDoS) via Cookie Name Injection |
| Alta | [GHSA-j5f8-grm9-p9fc](https://osv.dev/vulnerability/GHSA-j5f8-grm9-p9fc) | CVE-2026-44486 | `axios` | 0.21.0 | 0.32.0 | Axios: Proxy-Authorization header leaks to redirect target when proxy is re-evaluated to direct connection |
| Alta | [GHSA-jr5f-v2jv-69x6](https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6) | CVE-2025-27152 | `axios` | 0.21.0 | 0.30.0 | axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL |
| Alta | [GHSA-p92q-9vqr-4j8v](https://osv.dev/vulnerability/GHSA-p92q-9vqr-4j8v) | CVE-2026-44487 | `axios` | 0.21.0 | 0.32.0 | Axios: Proxy-Authorization Credential Leak to Origin Server Across HTTP-to-HTTPS Redirect in Axios Node.js HTTP Adapter |
| Alta | [GHSA-pf86-5x62-jrwf](https://osv.dev/vulnerability/GHSA-pf86-5x62-jrwf) | CVE-2026-42033 | `axios` | 0.21.0 | 0.31.1 | Axios: Prototype Pollution Gadgets - Response Tampering, Data Exfiltration, and Request Hijacking |
| Alta | [GHSA-pjwm-pj3p-43mv](https://osv.dev/vulnerability/GHSA-pjwm-pj3p-43mv) | CVE-2026-44492 | `axios` | 0.21.0 | 0.32.0 | axios's shouldBypassProxy does not recognize IPv4-mapped IPv6 addresses, allowing NO_PROXY bypass (incomplete fix for CVE-2025-62718) |
| Alta | [GHSA-pmwg-cvhr-8vh7](https://osv.dev/vulnerability/GHSA-pmwg-cvhr-8vh7) | CVE-2026-42043 | `axios` | 0.21.0 | 0.31.1 | Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Protection Bypassed via RFC 1122 Loopback Subnet (127.0.0.0/8) in Axios 1.15.0 |
| Alta | [GHSA-3gh2-xw74-jmcw](https://osv.dev/vulnerability/GHSA-3gh2-xw74-jmcw) | CVE-2020-9402 | `django` | 3.0.0 | 3.0.4 | SQL injection in Django |
| Alta | [GHSA-6w2r-r2m5-xq5w](https://osv.dev/vulnerability/GHSA-6w2r-r2m5-xq5w) | CVE-2025-57833 | `django` | 3.0.0 | 4.2.24 | Django is subject to SQL injection through its column aliases |
| Alta | [GHSA-8x94-hmjh-97hq](https://osv.dev/vulnerability/GHSA-8x94-hmjh-97hq) | CVE-2022-36359 | `django` | 3.0.0 | 3.2.15 | Django vulnerable to Reflected File Download attack |
| Alta | [GHSA-m6gj-h9gm-gw44](https://osv.dev/vulnerability/GHSA-m6gj-h9gm-gw44) | CVE-2020-24583 | `django` | 3.0.0 | 3.0.10 | Django Incorrect Default Permissions |
| Alta | [GHSA-p99v-5w3c-jqq9](https://osv.dev/vulnerability/GHSA-p99v-5w3c-jqq9) | CVE-2021-33571 | `django` | 3.0.0 | 3.1.12 | Django Access Control Bypass possibly leading to SSRF, RFI, and LFI attacks |
| Alta | [GHSA-qw25-v68c-qjf3](https://osv.dev/vulnerability/GHSA-qw25-v68c-qjf3) | CVE-2025-64458 | `django` | 3.0.0 | 4.2.26 | Django has a denial-of-service vulnerability in HttpResponseRedirect and HttpResponsePermanentRedirect on Windows |
| Alta | [GHSA-rxjp-mfm9-w4wr](https://osv.dev/vulnerability/GHSA-rxjp-mfm9-w4wr) | CVE-2021-31542 | `django` | 3.0.0 | 3.1.9 | Path Traversal in Django |
| Alta | [GHSA-wpjr-j57x-wxfw](https://osv.dev/vulnerability/GHSA-wpjr-j57x-wxfw) | CVE-2020-13254 | `django` | 3.0.0 | 3.0.7 | Data leakage via cache key collision in Django |
| Alta | [GHSA-wvqv-fj8w-qmhm](https://osv.dev/vulnerability/GHSA-wvqv-fj8w-qmhm) | CVE-2026-15307 | `django` | 3.0.0 | 5.2.17 | Django GeoDjango spatial lookups allow file writes and outbound requests through GDAL raster parsing |
| Alta | [GHSA-m2qf-hxjv-5gpq](https://osv.dev/vulnerability/GHSA-m2qf-hxjv-5gpq) | CVE-2023-30861 | `flask` | 2.2.0 | 2.2.5 | Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header |
| Alta | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | `lodash` | 4.17.15 | 4.17.21 | Command Injection in lodash |
| Alta | [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) | CVE-2020-8203 | `lodash` | 4.17.15 | 4.17.19 | Prototype Pollution in lodash |
| Alta | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) | CVE-2026-4800 | `lodash` | 4.17.15 | 4.18.0 | lodash vulnerable to Code Injection via `_.template` imports key names |
| Alta | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | `lodash` | 4.17.15 | 4.17.21 | Command Injection in lodash |
| Alta | [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) | CVE-2020-8203 | `lodash` | 4.17.15 | 4.17.19 | Prototype Pollution in lodash |
| Alta | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) | CVE-2026-4800 | `lodash` | 4.17.15 | 4.18.0 | lodash vulnerable to Code Injection via `_.template` imports key names |
| Alta | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | `lodash` | 4.17.15 | 4.17.21 | Command Injection in lodash |
| Alta | [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) | CVE-2020-8203 | `lodash` | 4.17.15 | 4.17.19 | Prototype Pollution in lodash |
| Alta | [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) | CVE-2026-4800 | `lodash` | 4.17.15 | 4.18.0 | lodash vulnerable to Code Injection via `_.template` imports key names |
| Alta | [GHSA-37ch-88jc-xwx2](https://osv.dev/vulnerability/GHSA-37ch-88jc-xwx2) | CVE-2024-45296, CVE-2026-4867 | `path-to-regexp` | 0.1.7 | 0.1.13 | path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters |
| Alta | [GHSA-rhx6-c78j-4q9w](https://osv.dev/vulnerability/GHSA-rhx6-c78j-4q9w) | CVE-2024-52798 | `path-to-regexp` | 0.1.7 | 0.1.12 | path-to-regexp contains a ReDoS |
| Alta | [GHSA-hrpp-h998-j3pp](https://osv.dev/vulnerability/GHSA-hrpp-h998-j3pp) | CVE-2022-24999 | `qs` | 6.7.0 | 6.7.3 | qs vulnerable to Prototype Pollution |
| Alta | [GHSA-hrpp-h998-j3pp](https://osv.dev/vulnerability/GHSA-hrpp-h998-j3pp) | CVE-2022-24999 | `qs` | 6.7.0 | 6.7.3 | qs vulnerable to Prototype Pollution |
| Alta | [GHSA-x84v-xcm2-53pg](https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg) | CVE-2018-18074 | `requests` | 2.19.0 | 2.20.0 | Insufficiently Protected Credentials in Requests |
| Alta | [GHSA-2xpw-w6gg-jr37](https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37) | CVE-2025-66471 | `urllib3` | 1.24.1 | 2.6.0 | urllib3 streaming API improperly handles highly compressed data |
| Alta | [GHSA-38jv-5279-wg99](https://osv.dev/vulnerability/GHSA-38jv-5279-wg99) | CVE-2026-21441 | `urllib3` | 1.24.1 | 2.6.3 | Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API) |
| Alta | [GHSA-gm62-xv2j-4w53](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53) | CVE-2025-66418 | `urllib3` | 1.24.1 | 2.6.0 | urllib3 allows an unbounded number of links in the decompression chain |
| Alta | [GHSA-mh33-7rrq-662w](https://osv.dev/vulnerability/GHSA-mh33-7rrq-662w) | CVE-2019-11324 | `urllib3` | 1.24.1 | 1.24.2 | Improper Certificate Validation in urllib3 |
| Alta | [GHSA-qccp-gfcp-xxvc](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc) | CVE-2026-44431 | `urllib3` | 1.24.1 | 2.7.0 | urllib3: Sensitive headers forwarded across origins in proxied low-level redirects |
| Alta | [GHSA-v845-jxx5-vc9f](https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f) | CVE-2023-43804 | `urllib3` | 1.24.1 | 1.26.17 | `Cookie` HTTP header isn't stripped on cross-origin redirects |
| Alta | [GHSA-vxq7-64xx-v4gw](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw) | CVE-2026-97689 | `urllib3` | 1.24.1 | 2.8.0 | urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory |
| Alta | [GHSA-2xpw-w6gg-jr37](https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37) | CVE-2025-66471 | `urllib3` | 1.26.4 | 2.6.0 | urllib3 streaming API improperly handles highly compressed data |
| Alta | [GHSA-38jv-5279-wg99](https://osv.dev/vulnerability/GHSA-38jv-5279-wg99) | CVE-2026-21441 | `urllib3` | 1.26.4 | 2.6.3 | Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API) |
| Alta | [GHSA-8988-9cw3-xx77](https://osv.dev/vulnerability/GHSA-8988-9cw3-xx77) | CVE-2026-97687 | `urllib3` | 1.26.4 | 2.8.0 | urllib3: HTTPS proxy TLS configuration may be ignored or overridden |
| Alta | [GHSA-gm62-xv2j-4w53](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53) | CVE-2025-66418 | `urllib3` | 1.26.4 | 2.6.0 | urllib3 allows an unbounded number of links in the decompression chain |
| Alta | [GHSA-q2q7-5pp4-w6pg](https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg) | CVE-2021-33503 | `urllib3` | 1.26.4 | 1.26.5 | Catastrophic backtracking in URL authority parser when passed URL containing many @ characters |
| Alta | [GHSA-qccp-gfcp-xxvc](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc) | CVE-2026-44431 | `urllib3` | 1.26.4 | 2.7.0 | urllib3: Sensitive headers forwarded across origins in proxied low-level redirects |
| Alta | [GHSA-v845-jxx5-vc9f](https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f) | CVE-2023-43804 | `urllib3` | 1.26.4 | 1.26.17 | `Cookie` HTTP header isn't stripped on cross-origin redirects |
| Alta | [GHSA-vxq7-64xx-v4gw](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw) | CVE-2026-97689 | `urllib3` | 1.26.4 | 2.8.0 | urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory |
| Média | [GHSA-3p68-rc4w-qgx5](https://osv.dev/vulnerability/GHSA-3p68-rc4w-qgx5) | CVE-2025-62718 | `axios` | 0.21.0 | 0.31.0 | Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF |
| Média | [GHSA-4w2v-q235-vp99](https://osv.dev/vulnerability/GHSA-4w2v-q235-vp99) | CVE-2020-28168 | `axios` | 0.21.0 | 0.21.1 | Axios vulnerable to Server-Side Request Forgery |
| Média | [GHSA-5c9x-8gcm-mpgx](https://osv.dev/vulnerability/GHSA-5c9x-8gcm-mpgx) | CVE-2026-42034 | `axios` | 0.21.0 | 0.31.1 | Axios' HTTP adapter-streamed uploads bypass maxBodyLength when maxRedirects: 0 |
| Média | [GHSA-62hf-57xw-28j9](https://osv.dev/vulnerability/GHSA-62hf-57xw-28j9) | CVE-2026-42039 | `axios` | 0.21.0 | 0.31.1 | Axios: unbounded recursion in toFormData causes DoS via deeply nested request data |
| Média | [GHSA-7q8q-rj6j-mhjq](https://osv.dev/vulnerability/GHSA-7q8q-rj6j-mhjq) | CVE-2026-67319 | `axios` | 0.21.0 | 0.33.0 | Axios: Nested axios option objects can consume polluted prototype values |
| Média | [GHSA-898c-q2cr-xwhg](https://osv.dev/vulnerability/GHSA-898c-q2cr-xwhg) | CVE-2026-44490 | `axios` | 0.21.0 | 0.32.0 | axios has DoS & Header Injection via Prototype Pollution Read-Side Gadgets in axios merge functions |
| Média | [GHSA-fvcv-3m26-pcqx](https://osv.dev/vulnerability/GHSA-fvcv-3m26-pcqx) | CVE-2026-40175 | `axios` | 0.21.0 | 0.31.0 | Axios has Unrestricted Cloud Metadata Exfiltration via Header Injection Chain |
| Média | [GHSA-m7pr-hjqh-92cm](https://osv.dev/vulnerability/GHSA-m7pr-hjqh-92cm) | CVE-2026-42038 | `axios` | 0.21.0 | 0.31.1 | Axios: no_proxy bypass via IP alias allows SSRF |
| Média | [GHSA-mmx7-hfxf-jppx](https://osv.dev/vulnerability/GHSA-mmx7-hfxf-jppx) | CVE-2026-67316 | `axios` | 0.21.0 | 0.33.0 | Axios: Prototype pollution gadgets can alter axios request construction |
| Média | [GHSA-vf2m-468p-8v99](https://osv.dev/vulnerability/GHSA-vf2m-468p-8v99) | CVE-2026-42036 | `axios` | 0.21.0 | 0.31.1 | Axios: HTTP adapter streamed responses bypass maxContentLength |
| Média | [GHSA-w9j2-pvgh-6h63](https://osv.dev/vulnerability/GHSA-w9j2-pvgh-6h63) | CVE-2026-42041 | `axios` | 0.21.0 | 0.31.1 | Axios: Authentication Bypass via Prototype Pollution Gadget in `validateStatus` Merge Strategy |
| Média | [GHSA-wf5p-g6vw-rhxx](https://osv.dev/vulnerability/GHSA-wf5p-g6vw-rhxx) | CVE-2023-45857 | `axios` | 0.21.0 | 0.28.0 | Axios Cross-Site Request Forgery Vulnerability |
| Média | [GHSA-xx6v-rp6x-q39c](https://osv.dev/vulnerability/GHSA-xx6v-rp6x-q39c) | CVE-2026-42042 | `axios` | 0.21.0 | 0.31.1 | Axios: XSRF Token Cross-Origin Leakage via Prototype Pollution Gadget in `withXSRFToken` Boolean Coercion |
| Média | [GHSA-2m34-jcjv-45xf](https://osv.dev/vulnerability/GHSA-2m34-jcjv-45xf) | CVE-2020-13596 | `django` | 3.0.0 | 3.0.7 | XSS in Django |
| Média | [GHSA-68w8-qjq3-2gfm](https://osv.dev/vulnerability/GHSA-68w8-qjq3-2gfm) | CVE-2021-33203 | `django` | 3.0.0 | 3.1.12 | Path Traversal in Django |
| Média | [GHSA-7xr5-9hcq-chf9](https://osv.dev/vulnerability/GHSA-7xr5-9hcq-chf9) | CVE-2025-48432 | `django` | 3.0.0 | 4.2.22 | Django Improper Output Neutralization for Logs vulnerability |
| Média | [GHSA-8qcx-xf44-272x](https://osv.dev/vulnerability/GHSA-8qcx-xf44-272x) | CVE-2026-53878 | `django` | 3.0.0 | 5.2.16 | Django: DomainNameValidator permits newline characters that may enable HTTP header injection |
| Média | [GHSA-crhf-3pfg-w68w](https://osv.dev/vulnerability/GHSA-crhf-3pfg-w68w) | CVE-2026-53877 | `django` | 3.0.0 | 5.2.16 | Django: GDALRaster may over-read heap memory when constructed from bytes |
| Média | [GHSA-fr28-569j-53c4](https://osv.dev/vulnerability/GHSA-fr28-569j-53c4) | CVE-2020-24584 | `django` | 3.0.0 | 3.0.10 | Django Incorrect Default Permissions |
| Média | [GHSA-fvgf-6h6h-3322](https://osv.dev/vulnerability/GHSA-fvgf-6h6h-3322) | CVE-2021-3281 | `django` | 3.0.0 | 3.0.12 | Django Directory Traversal via archive.extract |
| Média | [GHSA-q238-5cxm-5c9h](https://osv.dev/vulnerability/GHSA-q238-5cxm-5c9h) | CVE-2026-15830 | `django` | 3.0.0 | 5.2.17 | Django GeoDjango vulnerable to denial of service through deeply nested geometry collections |
| Média | [GHSA-rrqc-c2jx-6jgv](https://osv.dev/vulnerability/GHSA-rrqc-c2jx-6jgv) | CVE-2024-45231 | `django` | 3.0.0 | 4.2.16 | Django allows enumeration of user e-mail addresses |
| Média | [GHSA-v6rh-hp5x-86rv](https://osv.dev/vulnerability/GHSA-v6rh-hp5x-86rv) | CVE-2021-44420 | `django` | 3.0.0 | 3.1.14 | Potential bypass of an upstream access control based on URL paths in Django |
| Média | [GHSA-xgxc-v2qg-chmh](https://osv.dev/vulnerability/GHSA-xgxc-v2qg-chmh) | CVE-2021-28658 | `django` | 3.0.0 | 3.0.14 | Directory Traversal in Django |
| Média | [GHSA-rv95-896h-c2vc](https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc) | CVE-2024-29041 | `express` | 4.17.1 | 4.19.2 | Express.js Open Redirect in malformed URLs |
| Média | [GHSA-rv95-896h-c2vc](https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc) | CVE-2024-29041 | `express` | 4.17.1 | 4.19.2 | Express.js Open Redirect in malformed URLs |
| Média | [GHSA-cpwx-vrp4-4pq7](https://osv.dev/vulnerability/GHSA-cpwx-vrp4-4pq7) | CVE-2025-27516 | `jinja2` | 3.1.2 | 3.1.6 | Jinja2 vulnerable to sandbox breakout through attr filter selecting format method |
| Média | [GHSA-gmj6-6f8f-6699](https://osv.dev/vulnerability/GHSA-gmj6-6f8f-6699) | CVE-2024-56201 | `jinja2` | 3.1.2 | 3.1.5 | Jinja has a sandbox breakout through malicious filenames |
| Média | [GHSA-h5c8-rqwp-cp95](https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95) | CVE-2024-22195 | `jinja2` | 3.1.2 | 3.1.3 | Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter |
| Média | [GHSA-h75v-3vvj-5mfj](https://osv.dev/vulnerability/GHSA-h75v-3vvj-5mfj) | CVE-2024-34064 | `jinja2` | 3.1.2 | 3.1.4 | Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter |
| Média | [GHSA-q2x7-8rv6-6q7h](https://osv.dev/vulnerability/GHSA-q2x7-8rv6-6q7h) | CVE-2024-56326 | `jinja2` | 3.1.2 | 3.1.5 | Jinja has a sandbox breakout through indirect reference to format method |
| Média | [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) | CVE-2020-28500 | `lodash` | 4.17.15 | 4.17.21 | Regular Expression Denial of Service (ReDoS) in lodash |
| Média | [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) | CVE-2025-13465 | `lodash` | 4.17.15 | 4.17.23 | Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions |
| Média | [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) | CVE-2020-28500 | `lodash` | 4.17.15 | 4.17.21 | Regular Expression Denial of Service (ReDoS) in lodash |
| Média | [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) | CVE-2025-13465 | `lodash` | 4.17.15 | 4.17.23 | Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions |
| Média | [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) | CVE-2020-28500 | `lodash` | 4.17.15 | 4.17.21 | Regular Expression Denial of Service (ReDoS) in lodash |
| Média | [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) | CVE-2025-13465 | `lodash` | 4.17.15 | 4.17.23 | Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions |
| Média | [GHSA-4mjr-xmp4-gh2g](https://osv.dev/vulnerability/GHSA-4mjr-xmp4-gh2g) | CVE-2026-82417 | `qs` | 6.7.0 | 6.16.0 | qs: Denial of Service via Attacker Controlled isBuffer |
| Média | [GHSA-6pq8-jhm2-2vcw](https://osv.dev/vulnerability/GHSA-6pq8-jhm2-2vcw) | CVE-2026-110816 | `qs` | 6.7.0 | 6.16.1 | qs : qs.stringify with arrayFormat 'comma' throws an uncaught TypeError on array elements carrying a non-callable own toString (DoS) |
| Média | [GHSA-6rw7-vpxm-498p](https://osv.dev/vulnerability/GHSA-6rw7-vpxm-498p) | CVE-2025-15284 | `qs` | 6.7.0 | 6.14.1 | qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion |
| Média | [GHSA-4mjr-xmp4-gh2g](https://osv.dev/vulnerability/GHSA-4mjr-xmp4-gh2g) | CVE-2026-82417 | `qs` | 6.7.0 | 6.16.0 | qs: Denial of Service via Attacker Controlled isBuffer |
| Média | [GHSA-6pq8-jhm2-2vcw](https://osv.dev/vulnerability/GHSA-6pq8-jhm2-2vcw) | CVE-2026-110816 | `qs` | 6.7.0 | 6.16.1 | qs : qs.stringify with arrayFormat 'comma' throws an uncaught TypeError on array elements carrying a non-callable own toString (DoS) |
| Média | [GHSA-6rw7-vpxm-498p](https://osv.dev/vulnerability/GHSA-6rw7-vpxm-498p) | CVE-2025-15284 | `qs` | 6.7.0 | 6.14.1 | qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion |
| Média | [GHSA-9hjg-9r4m-mvj7](https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7) | CVE-2024-47081 | `requests` | 2.19.0 | 2.32.4 | Requests vulnerable to .netrc credentials leak via malicious URLs |
| Média | [GHSA-9wx4-h78v-vm56](https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56) | CVE-2024-35195 | `requests` | 2.19.0 | 2.32.0 | Requests `Session` object does not verify requests after making first request with verify=False |
| Média | [GHSA-gc5v-m9x4-r6x2](https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2) | CVE-2026-25645 | `requests` | 2.19.0 | 2.33.0 | Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function |
| Média | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) | CVE-2023-32681 | `requests` | 2.19.0 | 2.31.0 | Unintended leak of Proxy-Authorization header in requests |
| Média | [GHSA-34jh-p97f-mpxf](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf) | CVE-2024-37891 | `urllib3` | 1.24.1 | 1.26.19 | urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects |
| Média | [GHSA-g4mx-q9vg-27p4](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4) | CVE-2023-45803 | `urllib3` | 1.24.1 | 1.26.18 | urllib3's request body not stripped after redirect from 303 status changes request method to GET |
| Média | [GHSA-gwvm-45gx-3cf8](https://osv.dev/vulnerability/GHSA-gwvm-45gx-3cf8) | CVE-2018-25091 | `urllib3` | 1.24.1 | 1.24.2 | Authorization Header forwarded on redirect |
| Média | [GHSA-pq67-6m6q-mj2v](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v) | CVE-2025-50181 | `urllib3` | 1.24.1 | 2.5.0 | urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation |
| Média | [GHSA-r64q-w8jr-g9qp](https://osv.dev/vulnerability/GHSA-r64q-w8jr-g9qp) | CVE-2019-11236 | `urllib3` | 1.24.1 | 1.24.3 | Improper Neutralization of CRLF Sequences in urllib3 library for Python |
| Média | [GHSA-wqvq-5m8c-6g24](https://osv.dev/vulnerability/GHSA-wqvq-5m8c-6g24) | CVE-2020-26137 | `urllib3` | 1.24.1 | 1.25.9 | CRLF injection in urllib3 |
| Média | [GHSA-34jh-p97f-mpxf](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf) | CVE-2024-37891 | `urllib3` | 1.26.4 | 1.26.19 | urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects |
| Média | [GHSA-g4mx-q9vg-27p4](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4) | CVE-2023-45803 | `urllib3` | 1.26.4 | 1.26.18 | urllib3's request body not stripped after redirect from 303 status changes request method to GET |
| Média | [GHSA-pq67-6m6q-mj2v](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v) | CVE-2025-50181 | `urllib3` | 1.26.4 | 2.5.0 | urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation |
| Baixa | [GHSA-xhjh-pmcv-23jw](https://osv.dev/vulnerability/GHSA-xhjh-pmcv-23jw) | CVE-2026-42040 | `axios` | 0.21.0 | 0.31.1 | Axios: Null Byte Injection via Reverse-Encoding in AxiosURLSearchParams |
| Baixa | [GHSA-3h9f-r86x-qvjx](https://osv.dev/vulnerability/GHSA-3h9f-r86x-qvjx) | CVE-2026-48588 | `django` | 3.0.0 | 5.2.16 | Django: cache middleware may expose private responses when unrelated request cookies are present |
| Baixa | [GHSA-8cjm-8mp7-r2xf](https://osv.dev/vulnerability/GHSA-8cjm-8mp7-r2xf) | CVE-2026-8404 | `django` | 3.0.0 | 5.2.15 | Django: UpdateCacheMiddleware may disclose cached responses due to case-sensitive Cache-Control handling |
| Baixa | [GHSA-923m-gv2p-w5qp](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp) | CVE-2026-48587 | `django` | 3.0.0 | 5.2.15 | Django: has_vary_header may expose cached responses when Vary values contain whitespace |
| Baixa | [GHSA-h7pc-vwp9-298g](https://osv.dev/vulnerability/GHSA-h7pc-vwp9-298g) | CVE-2026-6873 | `django` | 3.0.0 | 5.2.15 | Django: signed cookies are vulnerable to salt namespace collisions |
| Baixa | [GHSA-qw6h-vgh9-j6wx](https://osv.dev/vulnerability/GHSA-qw6h-vgh9-j6wx) | CVE-2024-43796 | `express` | 4.17.1 | 4.20.0 | express vulnerable to XSS via response.redirect() |
| Baixa | [GHSA-qw6h-vgh9-j6wx](https://osv.dev/vulnerability/GHSA-qw6h-vgh9-j6wx) | CVE-2024-43796 | `express` | 4.17.1 | 4.20.0 | express vulnerable to XSS via response.redirect() |
| Baixa | [GHSA-68rp-wp8r-4726](https://osv.dev/vulnerability/GHSA-68rp-wp8r-4726) | CVE-2026-27205 | `flask` | 2.2.0 | 3.1.3 | Flask session does not add `Vary: Cookie` header when accessed in some ways |
| Baixa | [GHSA-w7fw-mjwx-w883](https://osv.dev/vulnerability/GHSA-w7fw-mjwx-w883) | CVE-2026-2391 | `qs` | 6.7.0 | 6.14.2 | qs's arrayLimit bypass in comma parsing allows denial of service |
| Baixa | [GHSA-w7fw-mjwx-w883](https://osv.dev/vulnerability/GHSA-w7fw-mjwx-w883) | CVE-2026-2391 | `qs` | 6.7.0 | 6.14.2 | qs's arrayLimit bypass in comma parsing allows denial of service |

> A ausência de uma vulnerabilidade neste relatório não garante que ela não exista: o Canary só conhece o que está catalogado na OSV.dev.
