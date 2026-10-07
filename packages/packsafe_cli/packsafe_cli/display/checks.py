"""Turns collected evidence into the per-check verdicts shown in the report.

Each builder answers one question about a package and returns a single
:class:`~packsafe.cli.display.theme.CheckRow`. Builders never print: they only translate
evidence into a label, a human-readable detail and a severity, which keeps the wording
testable and the layout free to change.
"""

from __future__ import annotations

from collections import Counter

from packsafe_core.models.scoring import Finding, ScoreResult, SeverityRank
from packsafe_core.pipeline.context import AnalysisContext

from .theme import (
    OK,
    RISK,
    SEVERITY_ORDER,
    UNKNOWN,
    WARN,
    CheckRow,
    human_days,
    human_int,
    plural,
    short_url,
)

# A release older than this reads as "stale", older than STALE_DAYS as "abandoned".
FRESH_DAYS = 90
STALE_DAYS = 365

# Download volume per month. Below WEAK the package is effectively unused; below
# LOW it is niche but real.
WEAK_DOWNLOADS = 100
LOW_DOWNLOADS = 1000


def build_checks(score: ScoreResult, ctx: AnalysisContext) -> list[CheckRow]:
    """Builds every check in report order."""
    return [
        _identity(ctx),
        _typosquatting(score, ctx),
        _repository(ctx),
        _vulnerabilities(score),
        _static_analysis(ctx),
        _maintenance(ctx),
        _adoption(ctx),
        _dependencies(ctx),
        _license(ctx),
    ]


def _identity(ctx: AnalysisContext) -> CheckRow:
    """Whether the package's declared identity holds up: repo agreement, publisher."""
    identity = ctx.identity

    if identity.status != "AVAILABLE":
        return CheckRow("Package identity", "identity evidence unavailable", UNKNOWN)

    notes: list[str] = []
    state = OK

    if identity.package_repo_mismatch:
        notes.append("declared repository does not match the resolved one")
        state = RISK
    if identity.publisher_anomaly_score:
        notes.append(f"publisher anomaly score {identity.publisher_anomaly_score:.0%}")
        state = RISK if state is RISK else WARN

    if not notes:
        return CheckRow("Package identity", "name, publisher and repository agree", OK)

    return CheckRow("Package identity", "; ".join(notes), state)


def _typosquatting(score: ScoreResult, ctx: AnalysisContext) -> CheckRow:
    """Name resemblance to a popular package, the classic typosquat vector."""
    identity = ctx.identity

    if identity.status != "AVAILABLE":
        return CheckRow("Typosquatting", "identity evidence unavailable", UNKNOWN)

    target = identity.target_popular_package
    if not target:
        return CheckRow("Typosquatting", "no resemblance to a popular package", OK)

    similarity = identity.name_similarity or 0.0
    detail = f'"{score.package_name}" vs "{target}" — {similarity:.0%} similar'

    if identity.typosquatting_risk:
        return CheckRow("Typosquatting", detail, RISK)

    return CheckRow("Typosquatting", detail, WARN)


def _repository(ctx: AnalysisContext) -> CheckRow:
    """Where the code lives and whether anyone is still working on it."""
    repo = ctx.repository
    url = repo.repository_url or ctx.package.repository_url

    if not url:
        return CheckRow("Repository", "no public repository linked", WARN)
    if repo.status != "AVAILABLE":
        return CheckRow("Repository", f"{short_url(url)} — activity unavailable", UNKNOWN)

    parts = [short_url(url)]
    if repo.stars is not None:
        parts.append(f"{human_int(repo.stars)} stars")
    if repo.forks is not None:
        parts.append(f"{human_int(repo.forks)} forks")
    if repo.recent_commits_90d is not None:
        parts.append(f"{plural(repo.recent_commits_90d, 'commit')} in 90d")

    if repo.is_archived:
        parts.append("archived")
        return CheckRow("Repository", " · ".join(parts), RISK)

    return CheckRow("Repository", " · ".join(parts), OK)


def _vulnerabilities(score: ScoreResult) -> CheckRow:
    """Advisories that actually affect the analyzed version, worst first."""
    vulns = [f for f in score.findings if f.category == "security"]

    if not vulns:
        return CheckRow("Vulnerabilities", "no known advisories affect this version", OK)

    counts = Counter(SeverityRank.from_str(f.severity).name for f in vulns)
    breakdown = ", ".join(
        f"{counts[rank]} {rank.lower()}" for rank in SEVERITY_ORDER if counts[rank]
    )

    worst = max(vulns, key=lambda f: SeverityRank.from_str(f.severity))
    verb = "affects" if len(vulns) == 1 else "affect"
    detail = f"{plural(len(vulns), 'advisory', 'advisories')} {verb} this version ({breakdown})"
    detail += f" · worst {worst.finding_id}"

    state = RISK if SeverityRank.from_str(worst.severity) >= SeverityRank.HIGH else WARN
    return CheckRow("Vulnerabilities", detail, state)


def _static_analysis(ctx: AnalysisContext) -> CheckRow:
    """What the archive inspection found inside the shipped code."""
    static = ctx.static_analysis

    if static.status != "AVAILABLE" or not static.scanned_files_count:
        return CheckRow("Static analysis", "distribution archive not inspected", UNKNOWN)

    scanned = plural(static.scanned_files_count, "file")
    findings = len(static.findings)

    if not findings:
        return CheckRow("Static analysis", f"no suspicious patterns in {scanned}", OK)

    return CheckRow(
        "Static analysis",
        f"{plural(findings, 'suspicious pattern')} in {scanned}",
        RISK,
    )


def _maintenance(ctx: AnalysisContext) -> CheckRow:
    """Release cadence and how long the project has been alive."""
    registry = ctx.registry

    if registry.status != "AVAILABLE":
        return CheckRow("Maintenance", "release history unavailable", UNKNOWN)

    parts: list[str] = []
    days = registry.days_since_last_release

    if days is None:
        state = UNKNOWN
        parts.append("last release date unknown")
    else:
        parts.append(f"last release {human_days(days)} ago")
        state = OK if days <= FRESH_DAYS else WARN if days <= STALE_DAYS else RISK

    if registry.release_count_1y is not None:
        parts.append(f"{plural(registry.release_count_1y, 'release')} in 12mo")
    if registry.maintainer_count is not None:
        parts.append(plural(registry.maintainer_count, "maintainer"))

    return CheckRow("Maintenance", " · ".join(parts), state)


def _adoption(ctx: AnalysisContext) -> CheckRow:
    """How much the ecosystem actually uses this package."""
    registry = ctx.registry
    parts: list[str] = []
    downloads = registry.downloads_30d

    if downloads is None:
        state = UNKNOWN
        parts.append("download volume unknown")
    else:
        parts.append(f"~{human_int(downloads)} downloads/month")
        state = OK if downloads >= LOW_DOWNLOADS else WARN if downloads >= WEAK_DOWNLOADS else RISK

    if registry.dependents_count is not None:
        parts.append(plural(registry.dependents_count, "dependent"))
    if registry.download_growth_rate is not None:
        parts.append(f"{registry.download_growth_rate:+.0%} growth")

    return CheckRow("Adoption", " · ".join(parts), state)


def _dependencies(ctx: AnalysisContext) -> CheckRow:
    """The shape of the dependency tree and whether it drags in trouble."""
    deps = ctx.dependencies

    if deps.status != "AVAILABLE":
        return CheckRow("Dependencies", "dependency graph unavailable", UNKNOWN)

    parts: list[str] = []
    if deps.direct_count is not None:
        parts.append(f"{deps.direct_count} direct")
    if deps.transitive_count is not None:
        parts.append(f"{deps.transitive_count} transitive")
    if deps.max_depth is not None:
        parts.append(f"depth {deps.max_depth}")

    if not parts:
        # Every count missing reads like "this package has no dependencies", which is a
        # very different claim from "we could not resolve its dependencies".
        return CheckRow("Dependencies", "dependency graph unavailable", UNKNOWN)

    state = OK
    if deps.vulnerable_dependency_count:
        parts.append(plural(deps.vulnerable_dependency_count, "vulnerable dependency"))
        state = RISK
    if deps.abandoned_count:
        parts.append(plural(deps.abandoned_count, "abandoned dependency"))
        state = RISK if state is RISK else WARN

    return CheckRow("Dependencies", " · ".join(parts), state)


def _license(ctx: AnalysisContext) -> CheckRow:
    """License clarity, which decides whether the package is usable at all."""
    lic = ctx.license

    if lic.status != "AVAILABLE":
        return CheckRow("License", "license evidence unavailable", UNKNOWN)

    declared = (lic.spdx_id or lic.declared_license or "").strip()
    if not declared or declared.upper() in ("UNKNOWN", "NONE", "NOASSERTION"):
        return CheckRow("License", "no license declared", WARN)

    parts = [declared]
    state = OK

    if lic.is_osi_approved:
        parts.append("OSI approved")
    else:
        parts.append("not OSI approved")
        state = WARN
    if lic.is_copyleft:
        parts.append("copyleft")

    # Only meaningful once the archive was actually opened: a missing license file and
    # an uninspected archive look identical from here otherwise.
    if ctx.static_analysis.status == "AVAILABLE" and not lic.license_file_present:
        parts.append("no license file in archive")
        state = WARN

    return CheckRow("License", " · ".join(parts), state)


def sort_findings(findings: tuple[Finding, ...]) -> list[Finding]:
    """Orders findings worst-first, then by how sure we are about them."""
    return sorted(
        findings,
        key=lambda f: (-SeverityRank.from_str(f.severity), -f.confidence, f.title),
    )
