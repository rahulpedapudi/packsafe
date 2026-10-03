"""deps.dev API collector for transitive dependency trees and dependents."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..config import settings
from ..models.dependencies import DependencyEvidence
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
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(url)

                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    return None
                elif resp.status_code == 429:
                    retry_after = float(
                        resp.headers.get("Retry-After", 1.0 + attempt * 2)
                    )
                    await asyncio.sleep(min(retry_after, 5.0))
                    continue
                elif resp.status_code >= 500:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                else:
                    return None
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.debug(f"deps.dev request error on attempt {attempt}: {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                else:
                    return None
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
            return DependencyEvidence(status="MISSING")

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        if not nodes:
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

        return DependencyNormalizer.merge_sources(
            root_package=package_name,
            deps_dev_graph=graph_nodes,
        )

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
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(lib_url)
                if resp.status_code == 200:
                    lib_data = resp.json()
                    cnt = lib_data.get("dependents_count")
                    if cnt is not None:
                        return (int(cnt), "libraries_io")
        except Exception as e:
            logger.error(f"Error collecting dependents count from libraries.io: {e}")

        return (None, "missing")


async def main():
    deps = DepsDevCollector()
    dep = await deps.collect_dependencies("requests", "2.32.0")
    # dep = await deps.collect_dependents_count("fastapi")
    print(dep)


if __name__ == "__main__":
    asyncio.run(main())
