# PackSafe

An intelligent security gatekeeper for the open-source supply chain. PackSafe evaluates
packages **before** installation and gives you a safety score, an explanation, and an
install gate.

## Install

```bash
uv tool install packsafe
# or
pipx install packsafe
# or, for a one-off run with no install at all
uvx packsafe analyze requests
```

## Use

```bash
packsafe analyze requests              # verdict: score, checks, risk factors
packsafe inspect django -V 5.2.8      # every piece of evidence, with provenance
packsafe install --pip requests       # gate, then install into the current environment
packsafe install --uv requests        # same, via uv
```

`install` is the part that matters. It refuses to install a package the policy blocks,
asks before installing one with warnings, and installs silently when it is safe:

| Result | What happens |
| --- | --- |
| No blocking signals | Installed |
| Warnings found | Prompts first (default: no). `--yes` for unattended use |
| Blocked by policy | Refused, exit code 4 |

Exit codes: `0` success · `1` not found or internal error · `2` registry unreachable ·
`3` bad package data · `4` blocked by policy · `5` no install target, or the package
manager failed.

### Where an install lands

Never a global environment. PackSafe installs into the environment belonging to the
directory you ran the command in, in this order of precedence:

1. `--python /path/to/env` — an environment directory or an interpreter
2. the active virtualenv (`$VIRTUAL_ENV`)
3. `./.venv`

With none of those present it stops and tells you, rather than installing somewhere you
did not ask for. Add `.packsafe/` to your `.gitignore` to keep the run directory out of
version control.

## What it looks at

Evidence is collected from PyPI, OSV.dev, GitHub, deps.dev, CISA KEV and FIRST EPSS, then
scored across five categories — security, integrity, supply chain, maintenance and
adoption. Each score is accompanied by the checks that fired and the evidence behind
them, so a number is never presented without a reason.

Every analysis records provenance: which source, which URL, when it was fetched, and the
archive hash the verdict was computed against.

### Logs

Diagnostics go to `./.packsafe/logs/packsafe.log`, never the working directory itself.
Override with `--log-file PATH` or `PACKSAFE_LOG_FILE`. It is a global option, so it
goes before the subcommand:

```bash
packsafe --log-file /tmp/packsafe.log analyze requests
```

## Under the hood

The scoring engine is deterministic and configuration-driven. The weight set, metrics and
gates live in `scoring/config/*.yaml`, and each run reports a SHA-256 over them so a score
can be reproduced or challenged later.

## License

Apache-2.0