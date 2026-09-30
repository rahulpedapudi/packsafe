"""GitHub Repository evidence collector with rate-limiting support and truthful activity queries."""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any
import httpx

from packsafe.evidence.models import (
    EvidenceProvenance,
    RepositoryEvidence,
)

logger = logging.getLogger(__name__)


class GitHubCollector:
    """Collects repository metrics from GitHub REST API v3."""

    def __init__(
        self,
        token: str | None = None,
        timeout: tuple[float, float] = (5.0, 15.0),
        max_retries: int = 2,
        client: httpx.Client | None = None,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.timeout = httpx.Timeout(connect=timeout[0], read=timeout[1], write=10.0, pool=10.0)
        self.max_retries = max_retries
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout, follow_redirects=True)

    def _execute_request(
        self,
        client: httpx.Client,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
    ) -> httpx.Response | None:
        import time
        for attempt in range(self.max_retries + 1):
            try:
                resp = client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    return resp
                elif resp.status_code in (403, 429):
                    retry_after = resp.headers.get("Retry-After")
                    sleep_s = min(float(retry_after), 5.0) if retry_after else (0.5 * (2 ** attempt))
                    if attempt < self.max_retries:
                        time.sleep(sleep_s)
                        continue
                    return resp
                elif resp.status_code >= 500:
                    if attempt < self.max_retries:
                        time.sleep(0.5 * (2 ** attempt))
                        continue
                    return resp
                else:
                    return resp
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                return None
        return None

    def extract_owner_repo(self, repo_url: str | None) -> tuple[str, str] | None:
        if not repo_url:
            return None
        m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+)", repo_url)
        if m:
            owner = m.group(1)
            repo = m.group(2).rstrip(".git")
            return (owner, repo)
        return None

    def collect(self, repo_url: str | None) -> tuple[RepositoryEvidence, EvidenceProvenance | None]:
        owner_repo = self.extract_owner_repo(repo_url)
        if not owner_repo:
            return (RepositoryEvidence(status="MISSING"), None)

        owner, repo = owner_repo
        base_url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {
            "User-Agent": "PackSafe-ScoreEngine",
            "Accept": "application/vnd.github.v3+json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        now = datetime.now(timezone.utc)
        client = self._get_client()

        try:
            resp = self._execute_request(client, base_url, headers=headers)
            if resp and resp.status_code == 200:
                data = resp.json()

                # Query commit count over last 90 days
                since_90d = (now - timedelta(days=90)).isoformat()
                recent_commits = self._fetch_recent_commits(client, owner, repo, since_90d, headers)
                recent_issues = self._fetch_recent_issues(client, owner, repo, since_90d, headers)

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

    def _count_paginated_items(
        self,
        client: httpx.Client,
        url: str,
        params: dict[str, Any],
        headers: dict[str, str],
    ) -> int | None:
        """Fetches total item count using GitHub Link header pagination."""
        resp = self._execute_request(client, url, headers=headers, params=params)
        if not resp or resp.status_code != 200:
            return None
        items = resp.json()
        if not isinstance(items, list):
            return None

        link = resp.headers.get("link") or resp.headers.get("Link")
        if not link:
            return len(items)

        # Parse rel="last"
        m = re.search(r'[?&]page=(\d+)[^>]*>;\s*rel="last"', link)
        if m:
            last_page = int(m.group(1))
            if last_page <= 1:
                return len(items)

            # Fetch last page to count remainder
            last_params = dict(params)
            last_params["page"] = last_page
            last_resp = self._execute_request(client, url, headers=headers, params=last_params)
            if last_resp and last_resp.status_code == 200:
                last_items = last_resp.json()
                if isinstance(last_items, list):
                    per_page = int(params.get("per_page", 100))
                    return (last_page - 1) * per_page + len(last_items)

            # Fallback if last page fails: estimate
            return (last_page - 1) * int(params.get("per_page", 100)) + len(items)

        # If rel="next" is present without rel="last", paginate forward up to 5 pages (500 items max)
        if 'rel="next"' in link:
            total_count = len(items)
            current_link = link
            current_page = 2
            while current_page <= 5 and 'rel="next"' in current_link:
                page_params = dict(params)
                page_params["page"] = current_page
                next_resp = self._execute_request(client, url, headers=headers, params=page_params)
                if not next_resp or next_resp.status_code != 200:
                    break
                next_items = next_resp.json()
                if not isinstance(next_items, list) or not next_items:
                    break
                total_count += len(next_items)
                current_link = next_resp.headers.get("link") or next_resp.headers.get("Link") or ""
                current_page += 1
            return total_count

        return len(items)

    def _fetch_recent_commits(
        self,
        client: httpx.Client,
        owner: str,
        repo: str,
        since_iso: str,
        headers: dict[str, str],
    ) -> int | None:
        """Fetches count of commits on default branch since timestamp."""
        url = f"https://api.github.com/repos/{owner}/{repo}/commits"
        params = {"since": since_iso, "per_page": 100}
        return self._count_paginated_items(client, url, params, headers)

    def _fetch_recent_issues(
        self,
        client: httpx.Client,
        owner: str,
        repo: str,
        since_iso: str,
        headers: dict[str, str],
    ) -> int | None:
        """Fetches count of issues updated since timestamp."""
        url = f"https://api.github.com/repos/{owner}/{repo}/issues"
        params = {"since": since_iso, "state": "all", "per_page": 100}
        return self._count_paginated_items(client, url, params, headers)
