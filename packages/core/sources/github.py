# """GitHub Repository evidence collector with rate-limiting support and truthful activity queries."""

# import asyncio
# import logging
# import os
# import re
# from datetime import UTC, datetime, timedelta
# from typing import Any

# import httpx

# from ..config import settings
# from ..models.evidence import EvidenceProvenance, RepositoryEvidence

# logger = logging.getLogger(__name__)


# class GitHubCollector:
#     """Collects repository metrics from GitHub REST API v3."""

#     # without token, you get 60 requests per hour
#     def __init__(
#         self,
#         token: str | None = None,
#         timeout: tuple[float, float] = (5.0, 15.0),
#         max_retries: int = 2,
#     ) -> None:

#         self.token = token or os.environ.get("GITHUB_TOKEN")
#         self.timeout = httpx.Timeout(
#             connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
#         )

#         self.max_retries = max_retries

#     async def _execute_request(
#         self,
#         url: str,
#         headers: dict[str, str],
#         params: dict[str, Any] | None = None,
#     ) -> httpx.Response | None:
#         """Execute HTTP request with exponential backoff retry logic."""

#         async with httpx.AsyncClient(
#             timeout=self.timeout, follow_redirects=True
#         ) as client:
#             for attempt in range(self.max_retries + 1):
#                 logger.info(f"Attempt {attempt}: {url}")
#                 try:
#                     resp = await client.get(url, headers=headers, params=params)

#                     if resp.status_code == 200:
#                         logger.info(f"Attempt {attempt}: {url} - Success")
#                         return resp

#                     elif resp.status_code in (403, 429):
#                         logger.warning(f"Attempt {attempt}: {url} - Rate limit")
#                         retry_after = resp.headers.get("Retry-After")
#                         sleep_s = (
#                             min(float(retry_after), 5.0)
#                             if retry_after
#                             else (0.5 * (2**attempt))
#                         )

#                         if attempt < self.max_retries:
#                             await asyncio.sleep(sleep_s)
#                             continue
#                         return resp

#                     elif resp.status_code >= 500:
#                         logger.warning(f"Attempt {attempt}: {url} - Server error")
#                         if attempt < self.max_retries:
#                             await asyncio.sleep(0.5 * (2**attempt))
#                             continue
#                         return resp

#                     else:
#                         logger.warning(f"Attempt {attempt}: {url} - Other error")
#                         return resp

#                 except (httpx.TimeoutException, httpx.NetworkError):
#                     logger.warning(f"Attempt {attempt}: {url} - Network error")
#                     if attempt < self.max_retries:
#                         await asyncio.sleep(0.5 * (2**attempt))
#                         continue
#                     return None
#         return None

#     def extract_owner_repo(self, repo_url: str | None) -> tuple[str, str] | None:
#         if not repo_url:
#             return None
#         m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+)", repo_url)
#         if m:
#             owner = m.group(1)
#             repo = m.group(2).removesuffix(".git")
#             return (owner, repo)
#         return None

#     async def collect(
#         self, repo_url: str | None
#     ) -> tuple[RepositoryEvidence, EvidenceProvenance | None]:
#         """Collect repository evidence from GitHub."""

#         owner_repo = self.extract_owner_repo(repo_url)

#         if not owner_repo:
#             return (RepositoryEvidence(status="MISSING"), None)

#         owner, repo = owner_repo
#         base_url = f"{settings.GITHUB_URL}/{owner}/{repo}"

#         headers = {
#             "Accept": "application/vnd.github.v3+json",
#         }

#         if self.token:
#             headers["Authorization"] = f"Bearer {self.token}"

#         now = datetime.now(UTC)

#         try:
#             resp = await self._execute_request(base_url, headers=headers)

#             if resp and resp.status_code == 200:
#                 data = resp.json()
#                 # logger.info(f"data: {data}")

#                 # Query commit count over last 90 days
#                 since_90d = (now - timedelta(days=90)).isoformat()
#                 recent_commits = await self._fetch_recent_commits(
#                     owner, repo, since_90d, headers
#                 )
#                 recent_issues = await self._fetch_recent_issues(
#                     owner, repo, since_90d, headers
#                 )

#                 repo_ev = RepositoryEvidence(
#                     repository_url=data.get("html_url", repo_url),
#                     stars=data.get("stargazers_count"),
#                     forks=data.get("forks_count"),
#                     watchers=data.get("subscribers_count"),
#                     open_issues=data.get("open_issues_count"),
#                     recent_commits_90d=recent_commits,
#                     recent_issues_90d=recent_issues,
#                     is_archived=bool(data.get("archived", False)),
#                     default_branch=data.get("default_branch", "main"),
#                     status="AVAILABLE",
#                 )
#                 prov = EvidenceProvenance(
#                     source="github",
#                     source_url=base_url,
#                     retrieved_at=now,
#                 )
#                 return (repo_ev, prov)
#             elif resp and resp.status_code in (403, 429):
#                 logger.warning(f"GitHub rate limit exceeded querying {owner}/{repo}.")

#             elif resp and resp.status_code == 404:
#                 logger.info(f"GitHub repository {owner}/{repo} not found (404).")

#         except Exception as e:
#             logger.debug(f"GitHub collection error for {owner}/{repo}: {e}")

#         return (RepositoryEvidence(status="MISSING"), None)

#     async def _count_paginated_items(
#         self, url: str, params: dict[str, Any], headers: dict[str, str]
#     ) -> int | None:
#         """Fetches total item count using GitHub Link header pagination."""

#         resp = await self._execute_request(url, headers=headers, params=params)

#         if not resp or resp.status_code != 200:
#             return None

#         items = resp.json()

#         if not isinstance(items, list):
#             return None

#         link = resp.headers.get("link") or resp.headers.get("Link")
#         if not link:
#             return len(items)

#         # Parse rel="last"
#         m = re.search(r'[?&]page=(\d+)[^>]*>;\s*rel="last"', link)
#         if m:
#             last_page = int(m.group(1))
#             if last_page <= 1:
#                 return len(items)

#             # Fetch last page to count remainder
#             last_params = dict(params)
#             last_params["page"] = last_page
#             last_resp = await self._execute_request(
#                 url, headers=headers, params=last_params
#             )
#             if last_resp and last_resp.status_code == 200:
#                 last_items = last_resp.json()
#                 if isinstance(last_items, list):
#                     per_page = int(params.get("per_page", 100))
#                     return (last_page - 1) * per_page + len(last_items)

#             # Fallback if last page fails: estimate
#             return (last_page - 1) * int(params.get("per_page", 100)) + len(items)

#         # If rel="next" is present without rel="last", paginate forward up to 5 pages (500 items max)
#         if 'rel="next"' in link:
#             total_count = len(items)
#             current_link = link
#             current_page = 2
#             while current_page <= 5 and 'rel="next"' in current_link:
#                 page_params = dict(params)
#                 page_params["page"] = current_page
#                 next_resp = await self._execute_request(
#                     url, headers=headers, params=page_params
#                 )
#                 if not next_resp or next_resp.status_code != 200:
#                     break
#                 next_items = next_resp.json()
#                 if not isinstance(next_items, list) or not next_items:
#                     break
#                 total_count += len(next_items)
#                 current_link = (
#                     next_resp.headers.get("link") or next_resp.headers.get("Link") or ""
#                 )
#                 current_page += 1
#             return total_count

#         return len(items)

#     async def _fetch_recent_commits(
#         self,
#         owner: str,
#         repo: str,
#         since_iso: str,
#         headers: dict[str, str],
#     ) -> int | None:
#         """Fetches count of commits on default branch since timestamp."""
#         url = f"{settings.GITHUB_URL}/{owner}/{repo}/commits"

#         params = {"since": since_iso, "per_page": 100}

#         return await self._count_paginated_items(url, params, headers)

#     async def _fetch_recent_issues(
#         self,
#         owner: str,
#         repo: str,
#         since_iso: str,
#         headers: dict[str, str],
#     ) -> int | None:
#         """Fetches count of issues updated since timestamp."""
#         url = f"{settings.GITHUB_URL}/{owner}/{repo}/issues"

#         params = {"since": since_iso, "state": "all", "per_page": 100}

#         return await self._count_paginated_items(url, params, headers)


# async def main():
#     collector = GitHubCollector()
#     repo_ev, provenance = await collector.collect("https://github.com/fastapi/fastapi")
#     print(repo_ev)
#     print(provenance)


# if __name__ == "__main__":
#     asyncio.run(main())
"""GitHub Repository evidence collector with rate-limiting support and truthful activity queries."""

import asyncio
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from ..config import settings
from ..models.evidence import EvidenceProvenance, RepositoryEvidence

logger = logging.getLogger(__name__)


class GitHubCollector:
    """Collects repository metrics from GitHub REST API v3."""

    # without token, you get 60 requests per hour
    def __init__(
        self,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: tuple[float, float] = (5.0, 15.0),
        max_retries: int = 2,
    ) -> None:

        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )

        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Lazily create one shared client so connections are pooled and reused."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def __aenter__(self) -> "GitHubCollector":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def _execute_request(
        self,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
    ) -> httpx.Response | None:
        """Execute HTTP request with exponential backoff retry logic."""

        client = self._get_client()

        for attempt in range(self.max_retries + 1):
            logger.info(f"Attempt {attempt}: {url}")
            try:
                resp = await client.get(url, headers=headers, params=params)

                if resp.status_code == 200:
                    logger.info(f"Attempt {attempt}: {url} - Success")
                    return resp

                elif resp.status_code in (403, 429):
                    logger.warning(f"Attempt {attempt}: {url} - Rate limit")
                    retry_after = resp.headers.get("Retry-After")
                    sleep_s = (
                        min(float(retry_after), 5.0)
                        if retry_after
                        else (0.5 * (2**attempt))
                    )

                    if attempt < self.max_retries:
                        await asyncio.sleep(sleep_s)
                        continue
                    return resp

                elif resp.status_code >= 500:
                    logger.warning(f"Attempt {attempt}: {url} - Server error")
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    return resp

                else:
                    logger.warning(f"Attempt {attempt}: {url} - Other error")
                    return resp

            except (httpx.TimeoutException, httpx.NetworkError):
                logger.warning(f"Attempt {attempt}: {url} - Network error")
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                return None
        return None

    def extract_owner_repo(self, repo_url: str | None) -> tuple[str, str] | None:
        if not repo_url:
            return None
        m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+)", repo_url)
        if m:
            owner = m.group(1)
            repo = m.group(2).removesuffix(".git")
            return (owner, repo)
        return None

    async def collect(
        self, repo_url: str | None
    ) -> tuple[RepositoryEvidence, EvidenceProvenance | None]:
        """Collect repository evidence from GitHub."""

        owner_repo = self.extract_owner_repo(repo_url)

        if not owner_repo:
            return (RepositoryEvidence(status="MISSING"), None)

        owner, repo = owner_repo
        base_url = f"{settings.GITHUB_URL}/{owner}/{repo}"

        headers = {
            "Accept": "application/vnd.github.v3+json",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        now = datetime.now(UTC)
        since_90d = (now - timedelta(days=90)).isoformat()

        try:
            # Owner/repo come from the URL, so none of these depend on each other.
            # Fire them all at once: ~1 round trip instead of 3 sequential ones.
            resp, recent_commits, recent_issues = await asyncio.gather(
                self._execute_request(base_url, headers=headers),
                self._fetch_recent_commits(owner, repo, since_90d, headers),
                self._fetch_recent_issues(owner, repo, since_90d, headers),
            )

            if resp and resp.status_code == 200:
                data = resp.json()

                repo_ev = RepositoryEvidence(
                    repository_url=data.get("html_url", repo_url),
                    stars=data.get("stargazers_count"),
                    forks=data.get("forks_count"),
                    watchers=data.get("subscribers_count"),
                    open_issues=data.get("open_issues_count"),
                    recent_commits_90d=recent_commits,
                    recent_issues_90d=recent_issues,
                    is_archived=bool(data.get("archived", False)),
                    default_branch=data.get("default_branch", "main"),
                    status="AVAILABLE",
                )
                prov = EvidenceProvenance(
                    source="github",
                    source_url=base_url,
                    retrieved_at=now,
                )
                return (repo_ev, prov)
            elif resp and resp.status_code in (403, 429):
                logger.warning(f"GitHub rate limit exceeded querying {owner}/{repo}.")

            elif resp and resp.status_code == 404:
                logger.info(f"GitHub repository {owner}/{repo} not found (404).")

        except Exception as e:
            logger.debug(f"GitHub collection error for {owner}/{repo}: {e}")

        return (RepositoryEvidence(status="MISSING"), None)

    async def _count_paginated_items(
        self, url: str, params: dict[str, Any], headers: dict[str, str]
    ) -> int | None:
        """Total item count in ONE request.

        Requests per_page=1, so the page number in the Link header's
        rel="last" is exactly the number of items. No Link header means
        everything fit on a single page (0 or 1 items).
        """

        count_params = {**params, "per_page": 1}
        resp = await self._execute_request(url, headers=headers, params=count_params)

        if not resp or resp.status_code != 200:
            return None

        items = resp.json()
        if not isinstance(items, list):
            return None

        link = resp.headers.get("link") or resp.headers.get("Link") or ""
        m = re.search(r'[?&]page=(\d+)[^>]*>;\s*rel="last"', link)
        if m:
            return int(m.group(1))

        return len(items)

    async def _fetch_recent_commits(
        self,
        owner: str,
        repo: str,
        since_iso: str,
        headers: dict[str, str],
    ) -> int | None:
        """Fetches count of commits on default branch since timestamp."""
        url = f"{settings.GITHUB_URL}/{owner}/{repo}/commits"

        params = {"since": since_iso}

        return await self._count_paginated_items(url, params, headers)

    async def _fetch_recent_issues(
        self,
        owner: str,
        repo: str,
        since_iso: str,
        headers: dict[str, str],
    ) -> int | None:
        """Fetches count of issues updated since timestamp."""
        url = f"{settings.GITHUB_URL}/{owner}/{repo}/issues"

        params = {"since": since_iso, "state": "all"}

        return await self._count_paginated_items(url, params, headers)


async def main():
    async with GitHubCollector() as collector:
        repo_ev, provenance = await collector.collect(
            "https://github.com/fastapi/fastapi"
        )
        print(repo_ev)
        print(provenance)


if __name__ == "__main__":
    asyncio.run(main())
