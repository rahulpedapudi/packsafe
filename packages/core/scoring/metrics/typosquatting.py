"""Typosquatting evaluation using RapidFuzz string similarity, versioned dictionary, and contextual risk."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any
from packsafe.evidence.models import PackageEvidence

try:
    from rapidfuzz import fuzz, distance
    HAS_RAPIDFUZZ = True
except ImportError:
    HAS_RAPIDFUZZ = False

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "popular_packages_v1.json"


def load_popular_targets() -> dict[str, list[str]]:
    """Loads versioned top popular package dictionary."""
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "pypi": data.get("pypi", []),
                    "npm": data.get("npm", []),
                }
        except Exception:
            pass

    # Default fallback
    return {
        "pypi": [
            "requests", "urllib3", "numpy", "pandas", "flask", "django", "pytest",
            "scipy", "cryptography", "boto3", "setuptools", "wheel", "pip", "pydantic",
            "tensorflow", "torch", "scikit-learn", "click", "fastapi", "certifi",
        ],
        "npm": [
            "react", "express", "lodash", "axios", "chalk", "commander", "vue",
            "next", "webpack", "typescript", "moment", "eslint", "jest", "rxjs",
        ],
    }


POPULAR_TARGETS = load_popular_targets()


def calculate_name_similarity(target: str, candidate: str) -> float:
    """Calculates composite string similarity between target and candidate package name in [0.0, 1.0]."""
    t = target.lower().strip()
    c = candidate.lower().strip()

    if t == c:
        return 1.0

    if HAS_RAPIDFUZZ:
        ratio_val = fuzz.ratio(t, c) / 100.0
        wratio_val = fuzz.WRatio(t, c) / 100.0
        dist = distance.Levenshtein.distance(t, c)
        max_len = max(len(t), len(c), 1)
        edit_sim = max(0.0, 1.0 - (dist / max_len))
        return max(ratio_val, wratio_val, edit_sim)
    else:
        ratio_val = difflib.SequenceMatcher(None, t, c).ratio()
        max_len = max(len(t), len(c), 1)
        matching_chars = sum(block.size for block in difflib.SequenceMatcher(None, t, c).get_matching_blocks())
        edit_sim = matching_chars / max_len
        return max(ratio_val, edit_sim)


def find_closest_popular_package(pkg_name: str, ecosystem: str = "pypi") -> tuple[str | None, float]:
    """Finds the closest popular package in the ecosystem and its similarity."""
    popular_list = POPULAR_TARGETS.get(ecosystem.lower(), POPULAR_TARGETS.get("pypi", []))
    best_target: str | None = None
    best_sim: float = 0.0

    for pop in popular_list:
        if pop.lower() == pkg_name.lower():
            continue
        sim = calculate_name_similarity(pop, pkg_name)
        if sim > best_sim:
            best_sim = sim
            best_target = pop

    return (best_target, best_sim)


def calculate_context_risk(evidence: PackageEvidence) -> float:
    """Calculates contextual trust anomaly score in [0.0, 1.0]."""
    # 1. Low adoption signal (35%)
    downloads = evidence.registry.downloads_30d
    if downloads is None or downloads < 100:
        s_low_adoption = 1.0
    elif downloads < 1000:
        s_low_adoption = 0.7
    elif downloads < 10000:
        s_low_adoption = 0.3
    else:
        s_low_adoption = 0.0

    # 2. New package signal (20%)
    maturity_days = evidence.registry.project_maturity_days
    if maturity_days is None or maturity_days < 30:
        s_new_pkg = 1.0
    elif maturity_days < 90:
        s_new_pkg = 0.6
    else:
        s_new_pkg = 0.0

    # 3. Weak/anomalous publisher signal (15%)
    s_weak_pub = evidence.identity.publisher_anomaly_score if evidence.identity.publisher_anomaly_score is not None else 0.0

    # 4. Missing repository signal (15%)
    repo_url = evidence.repository.repository_url or ""
    stars = evidence.repository.stars if evidence.repository.stars is not None else 0
    if not repo_url or stars < 5:
        s_missing_repo = 1.0
    else:
        s_missing_repo = 0.0

    # 5. Suspicious installation/static behavior signal (15%)
    has_suspicious_static = any(
        f.severity.upper() in ("HIGH", "CRITICAL")
        for f in evidence.static_analysis.findings
    )
    s_suspicious = 1.0 if has_suspicious_static else 0.0

    context_risk = (
        0.35 * s_low_adoption
        + 0.20 * s_new_pkg
        + 0.15 * s_weak_pub
        + 0.15 * s_missing_repo
        + 0.15 * s_suspicious
    )
    return max(0.0, min(1.0, context_risk))


class TyposquattingEvaluator:
    """Evaluates typosquatting similarity and contextual mimic risk."""

    def evaluate(self, evidence: PackageEvidence) -> tuple[float, str | None, float, float]:
        """Returns (typosquatting_risk, target_package, name_similarity, context_risk)."""
        pkg_name = evidence.package.name
        ecosystem = evidence.package.ecosystem

        # If identity evidence already provided custom target/sim, respect it
        if evidence.identity.target_popular_package and (evidence.identity.name_similarity or 0.0) > 0:
            target_pkg = evidence.identity.target_popular_package
            name_sim = float(evidence.identity.name_similarity)
        else:
            target_pkg, name_sim = find_closest_popular_package(pkg_name, ecosystem)

        if name_sim < 0.85:
            return (0.0, target_pkg, name_sim, 0.0)

        context_risk = (
            float(evidence.identity.context_risk)
            if (evidence.identity.context_risk is not None and evidence.identity.context_risk > 0)
            else calculate_context_risk(evidence)
        )

        typo_risk = name_sim * context_risk
        return (max(0.0, min(1.0, typo_risk)), target_pkg, name_sim, context_risk)
