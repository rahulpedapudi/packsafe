### Score is built from five independent dimensions

| Category     | Weight | Meaning                                            |
| ------------ | ------ | -------------------------------------------------- |
| Security     | 40%    | Known vulnerabilites posture and eploitation risk  |
| Integrity    | 25%    | Package identity and malicious/suspicious behavior |
| Supply Chain | 20 %   | Dependency exposure and structural complexity      |
| Maintenance  | 10%    | Project health and development activity            |
| Adoption     | 5%     | Community usage and adoption                       |

---

## Category Scope

- Security (40%) measures known vulnerability posture and exploitation risk: CVEs/GHSAs/OSV advisories,
  exposure depth, exploitability and active exploitation.
- Integrity (25%) measures package identity trust and package behavior: installation behavior, process execution,
  credential/secret access, dynamic execution, obfuscation, network activity and malicious/suspicious findings.
- Supply Chain (20%) measures dependency-tree exposure and structural complexity: counts, depth, churn and
  vulnerable dependency exposure.
- Maintenance (10%) measures project health and recent activity: releases, commits, issue activity, archival state
  and maintainers.
- Adoption (5%) measures community usage: downloads, growth, stars, forks, watchers and dependents.
