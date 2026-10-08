# packsafe-core

The evidence collection and security scoring engine behind
[PackSafe](https://github.com/rahulpedapudi/packsafe) — a security gatekeeper for the
open-source supply chain.

Most users should install the `packsafe` CLI, which depends on this package and pulls it
in automatically. Install `packsafe-core` directly only if you are embedding the pipeline
in your own tooling.

## What it does

Runs an analysis pipeline over a package, gathers evidence from the registry, the
vulnerability databases, the source repository and the distribution archive, and reduces
it to a single reproducible score.

```python
import asyncio

from packsafe_core.models.package import EcosystemType, PackageRequest
from packsafe_core.pipeline.analysis import AnalysisPipeline

outcome = asyncio.run(
    AnalysisPipeline().run_detailed(
        PackageRequest(name="requests", version="2.34.2", ecosystem=EcosystemType.pypi)
    )
)

print(outcome.score.final_score, outcome.score.risk_level.value)
print(outcome.score.decision.value)
```

`run_detailed` returns both the score and the evidence it was derived from. Use `run` if
you only want the score.

## The score is deterministic

The weight set, metrics, gates and coverage weights live in `scoring/config/*.yaml` rather
than in code. Every run reports a SHA-256 across those files, so a score can be
reproduced or challenged later:

```
engine 1.0.0 (config 2026-09-v1.2)  config SHA256 7a5289776d01…
```

Configuration is loaded through a validating schema; an invalid weight set raises rather
than silently scoring.

## What is collected

Registry metadata (PyPI), advisories (OSV.dev), exploitation signals (CISA KEV, FIRST
EPSS), repository activity (GitHub), dependency graphs (deps.dev) and static analysis of
the distribution archive. Each collector records provenance: which source, which URL, when
it was fetched, and the archive hash the verdict was computed against.

Collectors degrade rather than raise. An unreachable source produces `MISSING` evidence
and lowers the reported confidence instead of aborting the run — with the exception of
the registry lookup itself, which raises `RegistryAPIError`, because a package that
cannot be resolved cannot be scored.

## License

Apache-2.0