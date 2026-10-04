"""Package name similarity against a versioned popular-package dictionary.

Pure, offline and deterministic. Feeds the identity/typosquatting evidence used by the
identity stage. RapidFuzz is used when available, with a stdlib difflib fallback so no
extra dependency is required.
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "popular_packages_v1.json"

try:  # pragma: no cover - exercised only when the optional dep is installed
    from rapidfuzz import distance, fuzz

    HAS_RAPIDFUZZ = True
except ImportError:  # pragma: no cover
    HAS_RAPIDFUZZ = False


def load_popular_targets() -> dict[str, list[str]]:
    """Loads the versioned top-popular-package dictionary, per ecosystem."""
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {
                "pypi": data.get("pypi", []),
                "npm": data.get("npm", []),
            }
        except (OSError, ValueError) as e:
            logger.warning("Could not load popular package dictionary: %s", e)

    return {
        "pypi": [
            "requests",
            "urllib3",
            "numpy",
            "pandas",
            "flask",
            "django",
            "pytest",
            "scipy",
            "cryptography",
            "boto3",
            "setuptools",
            "wheel",
            "pip",
            "pydantic",
            "tensorflow",
            "torch",
            "scikit-learn",
            "click",
            "fastapi",
            "certifi",
        ],
        "npm": [
            "react",
            "express",
            "lodash",
            "axios",
            "chalk",
            "commander",
            "vue",
            "next",
            "webpack",
            "typescript",
            "moment",
            "eslint",
            "jest",
            "rxjs",
        ],
    }


POPULAR_TARGETS = load_popular_targets()


def calculate_name_similarity(target: str, candidate: str) -> float:
    """Composite string similarity in [0.0, 1.0] between two package names."""
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

    ratio_val = difflib.SequenceMatcher(None, t, c).ratio()
    max_len = max(len(t), len(c), 1)
    matching_chars = sum(
        block.size
        for block in difflib.SequenceMatcher(None, t, c).get_matching_blocks()
    )
    edit_sim = matching_chars / max_len
    return max(ratio_val, edit_sim)


def find_closest_popular_package(
    pkg_name: str, ecosystem: str = "pypi"
) -> tuple[str | None, float]:
    """Finds the closest popular package in the ecosystem and its similarity.

    An exact match is skipped: a package is not a typosquat of itself.
    """
    popular_list = POPULAR_TARGETS.get(
        ecosystem.lower(), POPULAR_TARGETS.get("pypi", [])
    )
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
