from packaging.requirements import Requirement


def parse_deps(dependencies: list[str]) -> list[dict]:

    result = []

    if not dependencies:
        return []

    for dep in dependencies:
        req = Requirement(dep)
        result.append({
            "name": req.name,
            "specifier": str(req.specifier),
        })

    return result
