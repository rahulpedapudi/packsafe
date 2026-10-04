"""deps.dev API collector for transitive dependency trees and dependents."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from ..config import settings
from ..models.dependencies import DependencyEvidence
from ..tracing import log_http
from .normalizers.dependency import DependencyNormalizer

logger = logging.getLogger(__name__)


class DepsDevCollector:
    """Collects dependency trees and dependents from Google deps.dev v3 API."""

    BASE_URL = settings.DEPS_URL

    def __init__(
        self,
        timeout: tuple[float, float] = (5.0, 15.0),
        max_retries: int = 2,
    ) -> None:

        self.base_url = self.BASE_URL

        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )

        self.max_retries = max_retries

    async def _execute_request(self, url: str) -> dict[str, Any] | None:
        """Executes HTTP request with exponential backoff and rate limit handling."""

        for attempt in range(self.max_retries + 1):
            request_start = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(url)
                request_elapsed = time.perf_counter() - request_start

                log_http(
                    logger,
                    "deps_dev",
                    method="GET",
                    url=url,
                    status=resp.status_code,
                    elapsed=request_elapsed,
                    attempt=attempt,
                )

                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    logger.info(
                        "deps.dev | 404 for %s: deps.dev has no record of this "
                        "package/version",
                        url,
                    )
                    return None
                elif resp.status_code == 429:
                    retry_after = float(
                        resp.headers.get("Retry-After", 1.0 + attempt * 2)
                    )
                    backoff = min(retry_after, 5.0)
                    logger.warning(
                        "deps.dev rate limited, sleeping %.1fs before attempt %d",
                        backoff,
                        attempt + 1,
                    )
                    await asyncio.sleep(backoff)
                    continue
                elif resp.status_code >= 500:
                    backoff = 0.5 * (2**attempt)
                    logger.warning(
                        "deps.dev server error %d, sleeping %.1fs before attempt %d",
                        resp.status_code,
                        backoff,
                        attempt + 1,
                    )
                    await asyncio.sleep(backoff)
                    continue
                else:
                    logger.warning(
                        "deps.dev unexpected HTTP %d for %s", resp.status_code, url
                    )
                    return None
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.warning(
                    "deps.dev network error on attempt %d/%d: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                else:
                    logger.warning(
                        "deps.dev gave up after %d attempts; dependency evidence MISSING",
                        self.max_retries + 1,
                    )
                    return None
        logger.warning(
            "deps.dev exhausted %d attempts without a usable response for %s",
            self.max_retries + 1,
            url,
        )
        return None

    async def collect_dependencies(
        self,
        package_name: str,
        version: str,
        ecosystem: str = "pypi",
    ) -> DependencyEvidence:
        """Queries deps.dev for package dependency tree and returns DependencyEvidence."""

        eco_norm = "pypi" if ecosystem.lower() == "pypi" else "npm"
        encoded_pkg = package_name.replace("/", "%2F")

        # build url
        # https://api.deps.dev/v3/systems/pypi/packages/requests/versions/2.33.0:dependencies
        url = f"{self.base_url}/systems/{eco_norm}/packages/{encoded_pkg}/versions/{version}:dependencies"

        data = await self._execute_request(url)
        if not data:
            logger.warning(
                "deps.dev dependency tree unavailable for %s==%s; supply-chain metrics "
                "will have no source",
                package_name,
                version,
            )
            return DependencyEvidence(status="MISSING")

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        if not nodes:
            logger.warning(
                "deps.dev returned 0 nodes for %s==%s", package_name, version
            )
            return DependencyEvidence(status="MISSING")

        # 1. Identify root node index
        root_idx = 0
        for idx, node in enumerate(nodes):
            relation = node.get("relation")
            pkg_name = node.get("versionKey", {}).get("name", "")
            if relation == "SELF" or pkg_name.lower() == package_name.lower():
                root_idx = idx
                break

        # 2. Build adjacency graph from edges
        # edges format: [{"fromNode": int, "toNode": int, "requirement": str}, ...]
        adj: dict[int, list[tuple[int, str]]] = {}
        for edge in edges:
            u = edge.get("fromNode")
            v = edge.get("toNode")
            req = edge.get("requirement", "")
            if u is not None and v is not None:
                adj.setdefault(u, []).append((v, req))

        # 3. BFS from root to compute exact depths and parent references
        from collections import deque

        visited: set[int] = {root_idx}
        queue: deque[tuple[int, int, str | None]] = deque([(root_idx, 0, None)])
        node_depth: dict[int, int] = {root_idx: 0}
        node_parent: dict[int, str | None] = {root_idx: None}
        node_req: dict[int, str] = {}

        while queue:
            curr_idx, curr_depth, _ = queue.popleft()
            curr_name = (
                nodes[curr_idx].get("versionKey", {}).get("name")
                if curr_idx < len(nodes)
                else None
            )
            for to_idx, req in adj.get(curr_idx, []):
                if to_idx not in visited and to_idx < len(nodes):
                    visited.add(to_idx)
                    node_depth[to_idx] = curr_depth + 1
                    node_parent[to_idx] = curr_name
                    node_req[to_idx] = req
                    queue.append((to_idx, curr_depth + 1, curr_name))

        # 4. Construct graph nodes for dependencies
        graph_nodes: list[dict[str, Any]] = []
        for idx, node in enumerate(nodes):
            if idx == root_idx:
                continue

            pkg_key = node.get("versionKey", {})
            name = pkg_key.get("name")
            ver = pkg_key.get("version")
            if not name or name.lower() == package_name.lower():
                continue

            if idx in node_depth:
                depth = node_depth[idx]
                parent = node_parent.get(idx)
            else:
                relation = node.get("relation", "TRANSITIVE")
                depth = 1 if relation == "DIRECT" else 2
                parent = None

            req = node_req.get(idx, "")

            graph_nodes.append(
                {
                    "name": name,
                    "version": ver,
                    "version_spec": req,
                    "depth": depth,
                    "parent": parent,
                    "is_archived": None,
                    "is_vulnerable": None,
                    "is_new": None,
                }
            )

        merged = DependencyNormalizer.merge_sources(
            root_package=package_name,
            deps_dev_graph=graph_nodes,
        )

        logger.info(
            "deps.dev dependency tree | graph_nodes=%d edges=%d root_index=%d -> "
            "direct=%s transitive=%s max_depth=%s",
            len(nodes),
            len(edges),
            root_idx,
            merged.direct_count,
            merged.transitive_count,
            merged.max_depth,
        )
        logger.debug(
            "deps.dev resolved dependencies | %s",
            {
                n["name"]: f"{n['version']} (depth={n['depth']}, spec={n['version_spec'] or 'none'})"
                for n in graph_nodes
            },
        )

        return merged

    async def collect_dependents_count(
        self,
        package_name: str,
        ecosystem: str = "pypi",
    ) -> tuple[int | None, str]:
        """Queries deps.dev (primary) or libraries.io (fallback) for dependent package count.

        Returns (dependents_count, source_name) where source_name is 'deps_dev',
        'libraries_io', or 'missing'.
        """
        eco_norm = "pypi" if ecosystem.lower() == "pypi" else "npm"
        encoded_pkg = package_name.replace("/", "%2F")

        # Fallback to libraries.io public package API
        lib_url = f"https://libraries.io/api/{eco_norm}/{encoded_pkg}"
        request_start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(lib_url)
            request_elapsed = time.perf_counter() - request_start

            log_http(
                logger,
                "libraries_io",
                method="GET",
                url=lib_url,
                status=resp.status_code,
                elapsed=request_elapsed,
            )

            if resp.status_code == 200:
                lib_data = resp.json()
                cnt = lib_data.get("dependents_count")
                if cnt is not None:
                    logger.info(
                        "dependents count | source=libraries_io count=%s", cnt
                    )
                    return (int(cnt), "libraries_io")
                logger.warning(
                    "libraries.io responded 200 for %s but returned no "
                    "dependents_count field",
                    package_name,
                )
        except Exception as e:
            logger.warning(
                "dependents count | libraries.io failed (%s: %s)",
                type(e).__name__,
                e,
            )

        logger.warning(
            "dependents count unavailable for %s from any source; the adoption "
            "metric dependents_count is MISSING",
            package_name,
        )
        return (None, "missing")


async def main():
    deps = DepsDevCollector()
    dep = await deps.collect_dependencies("requests", "2.32.0")
    # dep = await deps.collect_dependents_count("fastapi")
    print(dep)


if __name__ == "__main__":
    asyncio.run(main())
