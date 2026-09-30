"""Loader to convert synthetic JSON profiles into PackageEvidence objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from datetime import datetime

from packsafe.evidence.models import (
    DependencyEvidence,
    DependencyItem,
    EvidenceProvenance,
    IdentityEvidence,
    LicenseEvidence,
    PackageEvidence,
    PackageIdentity,
    RegistryEvidence,
    RepositoryEvidence,
    StaticAnalysisEvidence,
    StaticAnalysisFindingItem,
    VulnerabilityEvidence,
    VulnerabilityItem,
)

PROFILES_DIR = Path(__file__).parent


def load_profile_json(profile_name_or_path: str | Path) -> PackageEvidence:
    """Loads a JSON synthetic package profile into an immutable PackageEvidence object."""
    if isinstance(profile_name_or_path, Path):
        file_path = profile_name_or_path
    else:
        name = str(profile_name_or_path)
        if not name.endswith(".json"):
            name = f"{name}.json"
        file_path = PROFILES_DIR / name

    if not file_path.exists():
        raise FileNotFoundError(f"Profile fixture not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    pkg_data = data.get("package", {})
    identity = PackageIdentity(
        name=pkg_data.get("name", "unknown-package"),
        ecosystem=pkg_data.get("ecosystem", "pypi"),
        version=pkg_data.get("version", "1.0.0"),
        package_url=pkg_data.get("package_url"),
        repository_url=pkg_data.get("repository_url"),
        archive_hash=pkg_data.get("archive_hash"),
    )

    reg_data = data.get("registry", {})
    reg_status = reg_data.get("status", "AVAILABLE")
    if reg_status == "MISSING":
        registry = RegistryEvidence(status="MISSING")
    else:
        registry = RegistryEvidence(
            latest_version=reg_data.get("latest_version"),
            release_count_1y=reg_data.get("release_count_1y"),
            release_count_3m=reg_data.get("release_count_3m"),
            days_since_last_release=float(reg_data["days_since_last_release"]) if "days_since_last_release" in reg_data else None,
            project_maturity_days=float(reg_data["project_maturity_days"]) if "project_maturity_days" in reg_data else None,
            maintainer_count=reg_data.get("maintainer_count"),
            downloads_30d=reg_data.get("downloads_30d"),
            download_growth_rate=float(reg_data["download_growth_rate"]) if "download_growth_rate" in reg_data else None,
            declared_license=reg_data.get("declared_license"),
            status=reg_status,
        )

    repo_data = data.get("repository", {})
    repo_status = repo_data.get("status", "AVAILABLE")
    if repo_status == "MISSING":
        repository = RepositoryEvidence(status="MISSING")
    else:
        repository = RepositoryEvidence(
            repository_url=repo_data.get("repository_url", identity.repository_url),
            stars=repo_data.get("stars"),
            forks=repo_data.get("forks"),
            watchers=repo_data.get("watchers"),
            open_issues=repo_data.get("open_issues"),
            recent_commits_90d=repo_data.get("recent_commits_90d"),
            recent_issues_90d=repo_data.get("recent_issues_90d"),
            is_archived=bool(repo_data.get("is_archived", False)),
            default_branch=repo_data.get("default_branch", "main"),
            status=repo_status,
        )

    vuln_data = data.get("vulnerabilities", {})
    vuln_status = vuln_data.get("status", "AVAILABLE")
    vuln_items: list[VulnerabilityItem] = []
    if vuln_status != "MISSING":
        for v in vuln_data.get("items", []):
            vuln_items.append(VulnerabilityItem(
                vulnerability_id=v.get("id", "CVE-0000"),
                aliases=tuple(v.get("aliases", [])),
                severity=v.get("severity", "LOW"),
                exploitability=float(v.get("exploitability", 0.5)),
                exposure=float(v.get("exposure", 1.0)),
                actively_exploited=bool(v.get("actively_exploited", False)),
                affected_ranges=tuple(v.get("affected_ranges", [])),
                fixed_versions=tuple(v.get("fixed_versions", [])),
                summary=v.get("summary", ""),
                source=v.get("source", "osv"),
                applicability_status=v.get("applicability_status", "APPLICABLE"),
            ))
    vulnerabilities = VulnerabilityEvidence(
        items=tuple(vuln_items),
        status=vuln_status,
    )

    dep_data = data.get("dependencies", {})
    dep_status = dep_data.get("status", "AVAILABLE")
    if dep_status == "MISSING":
        dependencies = DependencyEvidence(status="MISSING")
    else:
        dependencies = DependencyEvidence(
            direct_count=dep_data.get("direct_count"),
            transitive_count=dep_data.get("transitive_count"),
            max_depth=dep_data.get("max_depth"),
            abandoned_count=dep_data.get("abandoned_count"),
            new_dependencies_count=dep_data.get("new_dependencies_count"),
            churn_rate=float(dep_data["churn_rate"]) if "churn_rate" in dep_data else None,
            vulnerable_dependency_count=dep_data.get("vulnerable_dependency_count"),
            status=dep_status,
        )

    static_data = data.get("static_analysis", {})
    static_status = static_data.get("status", "AVAILABLE")
    findings: list[StaticAnalysisFindingItem] = []
    if static_status != "MISSING":
        for f in static_data.get("findings", []):
            findings.append(StaticAnalysisFindingItem(
                finding_type=f.get("type", "UNKNOWN"),
                severity=f.get("severity", "LOW"),
                confidence=float(f.get("confidence", 0.8)),
                title=f.get("title", ""),
                description=f.get("description", ""),
                evidence_snippet=f.get("evidence", ""),
                file_path=f.get("file_path", "setup.py"),
                line_number=int(f.get("line", 1)),
            ))
    static_analysis = StaticAnalysisEvidence(
        findings=tuple(findings),
        scanned_files_count=int(static_data.get("scanned_files_count", 0)),
        archive_sha256=static_data.get("archive_sha256"),
        status=static_status,
    )

    id_data = data.get("identity", {})
    id_status = id_data.get("status", "AVAILABLE")
    identity_evidence = IdentityEvidence(
        target_popular_package=id_data.get("target_popular_package"),
        name_similarity=float(id_data["name_similarity"]) if "name_similarity" in id_data else None,
        context_risk=float(id_data["context_risk"]) if "context_risk" in id_data else None,
        typosquatting_risk=float(id_data["typosquatting_risk"]) if "typosquatting_risk" in id_data else None,
        publisher_anomaly_score=float(id_data["publisher_anomaly_score"]) if "publisher_anomaly_score" in id_data else None,
        package_repo_mismatch=bool(id_data.get("package_repo_mismatch", False)),
        status=id_status,
    )

    lic_data = data.get("license", {})
    lic_status = lic_data.get("status", "AVAILABLE")
    license_evidence = LicenseEvidence(
        declared_license=lic_data.get("declared_license"),
        spdx_id=lic_data.get("spdx_id", "UNKNOWN"),
        is_osi_approved=bool(lic_data.get("is_osi_approved", True)),
        is_copyleft=bool(lic_data.get("is_copyleft", False)),
        license_file_present=bool(lic_data.get("license_file_present", True)),
        status=lic_status,
    )

    return PackageEvidence(
        package=identity,
        registry=registry,
        repository=repository,
        vulnerabilities=vulnerabilities,
        dependencies=dependencies,
        static_analysis=static_analysis,
        identity=identity_evidence,
        license=license_evidence,
        analysis_coverage_tier=data.get("analysis_coverage_tier", "deep_static"),
    )
