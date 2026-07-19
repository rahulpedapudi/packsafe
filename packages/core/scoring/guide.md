### The Philosophy

We are not building one **Opaque** Formula. We need to build independent signal categories, each scored 0-100, then we combine with weights.

This way,

- Each category is explainable.
- We can tune weights per profile (Permissive/ Balanced/ Strict).
- A single bad signal (active malware) can override everything else.

### The Categories

1. **Maintenance Health**

   > **Weight: ~20%**

   | Signal              | Data Source                                    | Scoring Logic                                                           |
   | ------------------- | ---------------------------------------------- | ----------------------------------------------------------------------- |
   | Project age         | PyPI `upload_time` of first release            | `<30 days` = 0pts, `30d-1yr` = 40pts, `1-3yr` = 70pts, `3yr+` = 100pts  |
   | Release frequency   | PyPI release history                           | Days since last release: `<90d`=100, `90-365d`=60, `1-2yr`=30, `2yr+`=0 |
   | Maintainer count    | PyPI `maintainers` field / GitHub contributors | 1 maintainer = risky (bus factor), 2+ = safer                           |
   | Maintainer activity | GitHub commits in last 6mo                     | Active commits = healthy signal                                         |

2. **Vulnerability Exposure**

   > **Weight: ~30%**

   | Signal                 | Data Source                                     | Scoring Logic                                                      |
   | ---------------------- | ----------------------------------------------- | ------------------------------------------------------------------ |
   | Active CVEs            | OSV.dev API                                     | Any CVE with no fix = score caps at 20 regardless of other signals |
   | CVE severity           | OSV `severity` (CVSS)                           | Critical CVE = hard block in Strict profile                        |
   | Historical CVE density | OSV history / count over lifetime               | Frequent CVEs = pattern of poor security practice                  |
   | Time-to-patch          | Compare CVE disclosure date vs fix release date | Fast patching = trustworthy maintainers                            |

3. **Authenticity/ Typosquatting**

   > **Weight: ~20%**

   | Signal                             | Data Source                                                    | Scoring Logic                                                                                                   |
   | ---------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
   | Name similarity to top packages    | `rapidfuzz` against top 10k PyPI/npm list                      | Levenshtein distance normalized; >90% similarity to a much more popular package = red flag                      |
   | Download disparity                 | PyPI download stats (via pypistats.org) vs the similar package | If similarity high AND downloads are orders of magnitude lower = strong typosquat signal                        |
   | Publish recency + similarity combo | Cross-reference                                                | New package + high similarity + low downloads = compound risk, not additive — multiply the risk, don't just sum |
   | Maintainer overlap                 | Check if same maintainer publishes both                        | If same maintainer as the "real" package, likely a legit variant, not squat                                     |

4. **Community Trust**

   > **Weight: ~15%**

   | Signal          | Data Source                                        | Scoring Logic                                                                    |
   | --------------- | -------------------------------------------------- | -------------------------------------------------------------------------------- |
   | Downloads/month | pypistats.org API                                  | Log-scale, not linear — 200M vs 20M is a smaller trust delta than 200 vs 20      |
   | GitHub stars    | GitHub API                                         | Log-scale similarly                                                              |
   | Contributors    | GitHub API                                         | More contributors = harder to sneak in malicious code unnoticed                  |
   | Dependents      | `libraries.io` API or PyPI reverse dependency data | How many other packages depend on this one — high = de facto vetted by ecosystem |

5. **Install Behavior**

   > **Weight: ~15%**

   | Signal                   | Data Source                                     | Scoring Logic                                                                                                                      |
   | ------------------------ | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
   | Build system type        | PyPI metadata — wheel vs sdist-only             | Wheel available = no arbitrary code execution needed at install. sdist-only with `setup.py` = runs arbitrary Python during install |
   | Setup script analysis    | Static AST parse of `setup.py`/`setup.cfg`      | Flag `subprocess`, `os.system`, `urllib`/`requests` calls, `eval`/`exec` inside setup — these are classic malware injection points |
   | Post-install hooks       | npm `package.json` `scripts.postinstall`        | npm equivalent — this is the #1 npm supply chain attack vector, flag any postinstall script by default                             |
   | Binary/native extensions | Check for `.so`/`.pyd`/`.node` files in package | Not inherently bad, but increases attack surface — informational, not punitive                                                     |
