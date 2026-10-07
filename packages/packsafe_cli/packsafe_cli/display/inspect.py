"""Renders the PackSafe inspection view: everything we know, section by section.

``analyze`` answers "should I trust this?". ``inspect`` answers "what did PackSafe
actually find, and where did it come from?" It walks the evidence subsystems in the
order the pipeline collects them and prints the raw values, including the ones that are
missing, so a gap in the evidence is visible instead of silently missing.

The two long lists - advisories and static findings - are bounded by default so the view
stays readable; ``expand=True`` (the CLI's ``--all``) prints every one.
"""

from __future__ import annotations

from datetime import datetime

from packsafe_core.models.result import AnalysisOutcome
from packsafe_core.models.scoring import ScoreResult, SeverityRank
from packsafe_core.models.static_analysis import StaticAnalysisFindingItem
from packsafe_core.models.vulnerability import ExploitationSignal, VulnerabilityItem
from packsafe_core.pipeline.context import AnalysisContext
from packsafe_core.sources.normalizers.vulnerability import (
    VulnerabilityDeduplicator,
    evaluate_version_applicability,
)
from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from .layout import UNKNOWN, bullet, field_table, joined, print_fields, section
from .theme import SEVERITY_STYLE, STATUS_STYLE, human_days, short_hash, short_url

# Advisory lists and static findings both run to dozens of entries on an old, widely used
# package. Bounded by default, exhaustive with --all.
MAX_ADVISORIES = 20
MAX_STATIC_FINDINGS = 20

# Longest license value shown inline before it is summarized; see _declared_license.
LICENSE_INLINE_LIMIT = 48

# Timestamp granularity that is worth printing; seconds are noise in an evidence dump.
TIME_FORMAT = "%Y-%m-%d %H:%M UTC"

ECOSYSTEM_NAME = {"pypi": "PyPI", "npm": "npm"}


def render_inspection(console: Console, outcome: AnalysisOutcome, *, expand: bool = False) -> None:
    """Prints every evidence subsystem collected for a package."""
    score = outcome.score
    context = outcome.context

    console.print()
    _render_header(console, score, context)
    _render_request(console, context)
    _render_package(console, context)
    _render_registry(console, context)
    _render_repository(console, context)
    _render_identity(console, context)
    _render_vulnerabilities(console, score, context, expanded=expand)
    _render_dependencies(console, context)
    _render_static_analysis(console, context, expanded=expand)
    _render_license(console, context)
    _render_provenance(console, context)
    _render_coverage(console, score, context)


# ---------------------------------------------------------------------- header


def _render_header(console: Console, score: ScoreResult, ctx: AnalysisContext) -> None:
    console.print(Text("PackSafe Inspection", style="bold cyan"))
    console.rule()
    console.print()

    subject = " ".join(
        part
        for part in (
            score.package_name or ctx.request.name,
            f"v{score.version}" if score.version else None,
            f"({_ecosystem(score.ecosystem)})" if score.ecosystem else None,
        )
        if part
    )
    console.print(Padding(Text(f"What do we know about {subject}?", style="bold"), (0, 1, 0, 2)))
    console.print(
        Padding(
            Text(
                "The verdict lives in `packsafe analyze`; this is the evidence underneath it.",
                style="bright_black",
            ),
            (0, 1, 1, 2),
        )
    )


def _render_request(console: Console, ctx: AnalysisContext) -> None:
    request = ctx.request
    section(console, "Request")
    print_fields(
        console,
        [
            ("Requested", request.name),
            ("Version", request.version or f"latest ({ctx.package.version or 'unknown'})"),
            ("Ecosystem", _ecosystem(request.ecosystem)),
            ("Scan type", request.scan_type),
            ("Profile", request.profile),
            ("Collected at", _stamp(ctx.collected_at)),
        ],
    )


# ------------------------------------------------------------- evidence fields


def _render_package(console: Console, ctx: AnalysisContext) -> None:
    package = ctx.package
    section(console, "Package")
    print_fields(
        console,
        [
            ("Name", package.name),
            ("Ecosystem", _ecosystem(package.ecosystem)),
            ("Version", package.version),
            ("Package URL", _link(package.package_url)),
            ("Repository", _link(package.repository_url)),
            ("Distribution", _link(package.distribution_url)),
            ("Archive SHA256", short_hash(package.archive_hash, 16)),
            ("Registry integrity", _link(package.registry_integrity)),
        ],
    )


def _render_registry(console: Console, ctx: AnalysisContext) -> None:
    registry = ctx.registry
    section(console, "Registry")

    rows = [
        ("Source", _ecosystem(ctx.package.ecosystem)),
        ("Latest version", registry.latest_version),
        ("Published at", _stamp(registry.published_at)),
        ("Last release", _age(registry.days_since_last_release)),
        ("Project age", _age(registry.project_maturity_days)),
        ("Releases (12mo)", registry.release_count_1y),
        ("Releases (3mo)", registry.release_count_3m),
        ("Maintainers", registry.maintainer_count),
        ("Downloads (30d)", registry.downloads_30d),
        ("Download growth", _percent(registry.download_growth_rate)),
        ("Dependents", registry.dependents_count),
    ]
    # The source only means something next to a count. A collector that found nothing
    # reports its own name in this field, which is noise rather than evidence.
    if registry.dependents_count is not None:
        rows.append(("Dependents source", registry.dependents_source))

    rows.append(("Declared license", _declared_license(registry.declared_license)))
    rows.append(("Status", _status(registry.status)))

    print_fields(console, rows)


def _render_repository(console: Console, ctx: AnalysisContext) -> None:
    repo = ctx.repository
    section(console, "Repository")
    print_fields(
        console,
        [
            ("URL", _link(repo.repository_url)),
            ("Stars", repo.stars),
            ("Forks", repo.forks),
            ("Watchers", repo.watchers),
            ("Open issues", repo.open_issues),
            ("Commits (90d)", repo.recent_commits_90d),
            ("Issues (90d)", repo.recent_issues_90d),
            ("Archived", repo.is_archived),
            ("Default branch", repo.default_branch),
            ("Status", _status(repo.status)),
        ],
    )


def _render_identity(console: Console, ctx: AnalysisContext) -> None:
    identity = ctx.identity
    section(console, "Identity")

    rows = [
        ("Similar package", identity.target_popular_package),
        ("Name similarity", _ratio(identity.name_similarity)),
        ("Typosquatting risk", _ratio(identity.typosquatting_risk)),
        ("Context risk", _ratio(identity.context_risk)),
        ("Publisher anomaly", _ratio(identity.publisher_anomaly_score)),
        ("Repo mismatch", identity.package_repo_mismatch or None),
        ("Status", _status(identity.status)),
    ]
    print_fields(console, rows)


def _render_dependencies(console: Console, ctx: AnalysisContext) -> None:
    deps = ctx.dependencies
    section(console, "Dependencies")
    print_fields(
        console,
        [
            ("Direct", deps.direct_count),
            ("Transitive", deps.transitive_count),
            ("Max depth", deps.max_depth),
            ("Abandoned", deps.abandoned_count),
            ("Vulnerable", deps.vulnerable_dependency_count),
            ("New (30d)", deps.new_dependencies_count),
            ("Churn rate", deps.churn_rate),
            ("Status", _status(deps.status)),
        ],
    )


def _render_static_analysis(console: Console, ctx: AnalysisContext, *, expanded: bool) -> None:
    static = ctx.static_analysis
    section(console, "Static analysis")

    console.print(
        field_table(
            [
                ("Files scanned", static.scanned_files_count or None),
                ("Findings", len(static.findings) or None),
                ("Archive size", _bytes(static.archive_size_bytes)),
                ("Archive SHA256", short_hash(static.archive_sha256, 16)),
                ("Status", _status(static.status)),
            ]
        )
    )

    if not static.findings:
        console.print(
            Padding(
                Text("No suspicious patterns were flagged.", style="dim"),
                (0, 1, 0, 2),
            )
        )
        return

    findings = static.findings[: MAX_STATIC_FINDINGS if not expanded else None]
    for finding in findings:
        console.print(_static_finding_block(finding))

    hidden = len(static.findings) - len(findings)
    if hidden > 0:
        console.print(
            Padding(
                Text(
                    f"… {hidden} more static findings; re-run with --all",
                    style="bright_black",
                ),
                (0, 1, 0, 2),
            )
        )


def _static_finding_block(item: StaticAnalysisFindingItem) -> Text:
    block = Text()
    severity = item.severity.upper()
    block.append(f"  {severity}", style=SEVERITY_STYLE.get(severity, "white"))
    block.append(f"  {item.title}", style="bold")
    block.append(f"  ({item.file_path}:{item.line_number})", style="bright_black")

    if item.description:
        block.append(f"\n    {item.description}", style="dim")
    if item.evidence_snippet:
        block.append(f"\n    {item.evidence_snippet}", style="bright_black")

    block.append(
        f"\n    confidence {item.confidence:.0%} · {item.finding_type}", style="bright_black"
    )
    return block


def _render_license(console: Console, ctx: AnalysisContext) -> None:
    lic = ctx.license
    section(console, "License")
    print_fields(
        console,
        [
            ("Declared", _declared_license(lic.declared_license)),
            ("SPDX id", lic.spdx_id),
            ("OSI approved", lic.is_osi_approved),
            ("Copyleft", lic.is_copyleft or None),
            ("File in archive", lic.license_file_present),
            ("Status", _status(lic.status)),
        ],
    )


# --------------------------------------------------------------- vulnerabilities


def _render_vulnerabilities(
    console: Console, score: ScoreResult, ctx: AnalysisContext, *, expanded: bool
) -> None:
    evidence = ctx.vulnerabilities
    clusters = VulnerabilityDeduplicator().deduplicate(evidence.items)
    section(console, f"Vulnerabilities ({len(clusters)})")

    if len(clusters) != len(evidence.items):
        console.print(
            Padding(
                Text(
                    f"{len(evidence.items)} advisories from the sources, merged into "
                    f"{len(clusters)} by alias — `analyze` scores the merged set.",
                    style="bright_black",
                ),
                (0, 1, 0, 2),
            )
        )

    if not clusters:
        console.print(
            Padding(
                Text("No advisories were returned for this package.", style="dim"),
                (0, 1, 0, 2),
            )
        )
        console.print(
            Padding(
                Text(f"OSV queried: {_yes(evidence.osv_queried)}", style="bright_black"),
                (0, 1, 1, 2),
            )
        )
        return

    # Advisories are split by whether they actually touch the analyzed version. The
    # score engine only counts the applicable half, and an inspection that hid the rest
    # would misrepresent how much was checked.
    applicable, not_applicable, unknown = _partition_advisories(
        clusters, score.version or ctx.package.version or "", ctx.package.ecosystem or ""
    )

    for title, items in (
        (f"Affects version {score.version}", applicable),
        ("Does not affect this version", not_applicable),
        ("Could not be evaluated", unknown),
    ):
        if not items:
            continue
        console.print(Text(f"  {title} ({len(items)})", style="bold"))

        shown = items if expanded else items[:MAX_ADVISORIES]
        for item in shown:
            console.print(_advisory_block(item))

        hidden = len(items) - len(shown)
        if hidden > 0:
            console.print(
                Padding(
                    Text(f"    … {hidden} more; re-run with --all", style="bright_black"),
                    (0, 1, 0, 0),
                )
            )


def _partition_advisories(
    items: list[VulnerabilityItem], version: str, ecosystem: str
) -> tuple[list[VulnerabilityItem], list[VulnerabilityItem], list[VulnerabilityItem]]:
    """Splits advisories into affected, unaffected, and unevaluable for this version."""
    applicable: list[VulnerabilityItem] = []
    not_applicable: list[VulnerabilityItem] = []
    unknown: list[VulnerabilityItem] = []

    for item in items:
        status, affected = evaluate_version_applicability(
            version, item.affected_ranges, item.fixed_versions, ecosystem
        )
        if status == "INVALID" or not version:
            unknown.append(item)
        elif affected:
            applicable.append(item)
        else:
            not_applicable.append(item)

    return (
        sorted(applicable, key=_severity_key),
        sorted(not_applicable, key=_severity_key),
        sorted(unknown, key=_severity_key),
    )


def _severity_key(item: VulnerabilityItem) -> tuple[int, str]:
    """Worst first, with the id as a stable tiebreak so output never jitters."""
    return (-SeverityRank.from_str(item.severity), item.vulnerability_id)


def _advisory_block(item: VulnerabilityItem) -> Text:
    block = Text()
    severity = item.severity.upper()
    block.append(f"  {severity:<9}", style=SEVERITY_STYLE.get(severity, "white"))
    block.append(item.vulnerability_id, style="bold")

    signals = _exploitation_notes(item)
    if signals:
        block.append(f"  {' · '.join(signals)}", style="yellow")

    if item.summary:
        block.append(f"\n    {item.summary}", style="dim")
    if item.aliases:
        block.append(f"\n    aliases: {joined(item.aliases)}", style="bright_black")
    if item.fixed_versions:
        block.append(f"\n    fixed in: {joined(item.fixed_versions)}", style="bright_black")
    if item.affected_ranges:
        block.append(f"\n    affected: {joined(item.affected_ranges)}", style="bright_black")

    block.append(f"\n    source: {item.source}", style="bright_black")
    return block


def _exploitation_notes(item: VulnerabilityItem) -> list[str]:
    """Only facts the source data supports, never "actively exploited" on its own."""
    notes: list[str] = []

    if item.kev_date_added:
        notes.append(f"CISA KEV since {item.kev_date_added:%Y-%m-%d}")
    if item.known_ransomware_use:
        notes.append("ransomware use reported")
    if item.exploitation_signal not in (ExploitationSignal.NONE, None):
        notes.append(str(item.exploitation_signal))
    if item.epss_percentile is not None:
        notes.append(f"EPSS {item.epss_percentile:.0%} pct")
    elif item.epss_score is not None:
        notes.append(f"EPSS {item.epss_score:.1%}")

    return notes


# ------------------------------------------------------- provenance and coverage


def _render_provenance(console: Console, ctx: AnalysisContext) -> None:
    section(console, f"Sources ({len(ctx.provenance)})")

    if not ctx.provenance:
        console.print(
            Padding(Text("No provenance was recorded.", style="bright_black"), (0, 1, 0, 2))
        )
        return

    for record in ctx.provenance:
        head = Text()
        head.append(record.source, style="bold")
        head.append(f"  {short_url(record.source_url)}")
        console.print(Padding(bullet(head), (0, 1, 0, 2)))

        # Retrieval metadata hangs under the source name. Distribution URLs are long
        # enough to wrap, and keeping the metadata on its own line stops it from being
        # pushed off the end of a wrapped URL.
        meta = Text(f"fetched {_stamp(record.retrieved_at)}", style="bright_black")
        if record.archive_sha256:
            meta.append(f"  archive {short_hash(record.archive_sha256)}", style="bright_black")
        console.print(Padding(meta, (0, 1, 0, 4)))


def _render_coverage(console: Console, score: ScoreResult, ctx: AnalysisContext) -> None:
    coverage = score.evidence_coverage_summary
    total = sum(coverage.values()) if coverage else 0
    measured = ", ".join(
        f"{count} {name.lower()}"
        for name, count in coverage.items()
        if count and name != "available"
    )

    section(console, "Coverage")
    print_fields(
        console,
        [
            ("Tier", ctx.analysis_coverage_tier),
            ("Metrics measured", f"{coverage.get('available', 0)} of {total}" if total else None),
            ("Metrics unavailable", measured or None),
            ("Score engine", f"{score.engine_version} (config {score.config_version})"),
            ("Config SHA256", short_hash(score.config_sha256, 16)),
            ("Scored at", _stamp(score.analyzed_at)),
        ],
    )


# ------------------------------------------------------------------ formatting


def _stamp(value: datetime | None) -> str | None:
    return f"{value:{TIME_FORMAT}}" if value else None


def _age(days: int | None) -> str | None:
    """Renders an age, keeping the raw day count so nothing is lost to rounding."""
    if days is None:
        return None
    return f"{human_days(days)} ({days:,} days)"


def _status(value: object) -> Text:
    name = str(value)
    return Text(name, style=STATUS_STYLE.get(name, "white"))


def _link(url: str | None) -> str | None:
    return short_url(url) if url else None


def _ecosystem(value: object) -> str | None:
    """Registry name for an ecosystem, whether it arrives as an enum or a plain string."""
    if value is None:
        return None
    key = getattr(value, "value", value)
    return ECOSYSTEM_NAME.get(str(key), str(key))


def _declared_license(value: str | None) -> str | None:
    """Compacts the registry's free-text license field.

    Plenty of projects paste the whole license body into that field instead of an SPDX
    id. A thousand characters of it tells the reader nothing the License section does not
    already say, so a long value is summarized and pointed there instead.
    """
    if not value:
        return None

    collapsed = " ".join(value.split())
    if len(collapsed) <= LICENSE_INLINE_LIMIT:
        return collapsed

    head = collapsed[:LICENSE_INLINE_LIMIT].rsplit(" ", 1)[0]
    return f"{head}… ({len(collapsed):,} chars of license text — see License)"


def _ratio(value: float | None) -> str | None:
    return f"{value:.0%}" if value is not None else None


def _percent(value: float | None) -> str | None:
    return f"{value:+.1%}" if value is not None else None


def _bytes(size: int | None) -> str | None:
    if not size:
        return None
    for unit in ("B", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return UNKNOWN


def _yes(value: bool) -> str:
    return "yes" if value else "no"
