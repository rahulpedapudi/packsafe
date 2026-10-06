import logging

from cvss import CVSS2, CVSS3, CVSS4
from packaging.requirements import Requirement

logger = logging.getLogger(__name__)


def parse_deps(dependencies: list[str]) -> list[dict]:

    result = []

    if not dependencies:
        return []

    for dep in dependencies:
        req = Requirement(dep)
        result.append(
            {
                "name": req.name,
                "specifier": str(req.specifier),
            }
        )

    return result


def _to_float(x: object) -> float | None:
    return None if x is None else float(x)  # type: ignore[arg-type]


def calculate_severity(severity_record: list[dict]) -> tuple[float | None, str]:
    best: float | None = None

    for s in severity_record:
        vec = s.get("score", "")
        try:
            if vec.startswith("CVSS:4.0/"):
                score = _to_float(CVSS4(vec).base_score)
            elif vec.startswith("CVSS:3"):  # 3.0 and 3.1
                score = float(CVSS3(vec).scores()[0])  # (base, temporal, env)
            elif vec.startswith("AV:"):  # bare v2 vector
                score = _to_float(CVSS2(vec).scores()[0])
            else:
                continue
        except Exception as e:
            logger.info(f"Something went wrong {e}")
            continue

        if score is None:  # this is what narrows it to float
            continue

        best = (score) if best is None else max(best, score)

    if best is None:
        return None, "UNKNOWN"
    return float(best), bucket(best)


def bucket(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
