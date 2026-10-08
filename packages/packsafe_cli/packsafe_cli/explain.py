"""The client half of the explanation feature: turn a finished score into prose.

``analyze --explain`` produces a paragraph explaining *why* the score came out the way it
did, in language rather than in metric names. The wording of the score comes from the
deterministic engine; this package only asks a model to describe it.

What the CLI deliberately does *not* know: which model, which provider, or which API key
does the describing. Those live on the PackSafe server behind ``EXPLAIN_API_URL``, behind
``packsafe_core.explain.contract``. A user installs the CLI and gets explanations without
ever handling a provider credential, and the service can change models without a CLI
release. That division is the reason this is an HTTP client and not a call into a model
SDK - a client that imported a provider would have to be re-released every time the
provider choice changed.

The one guarantee this module makes is that an explanation can never affect a verdict.
:func:`request_explanation` returns ``None`` on every failure, and no caller is permitted
to turn that into an error: ``analyze``'s exit code and report are already final by the
time this runs.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Protocol

import httpx
from packsafe_core.config import settings
from packsafe_core.explain import Explanation, build_explain_request
from packsafe_core.models.result import AnalysisOutcome
from rich.console import Console

from .display.explain import render_explanation

logger = logging.getLogger(__name__)

ENV_URL = "PACKSAFE_EXPLAIN_URL"
ENV_TIMEOUT = "PACKSAFE_EXPLAIN_TIMEOUT"
ENV_TOKEN = "PACKSAFE_EXPLAIN_TOKEN"

DEFAULT_TIMEOUT = 60.0

# A model writing four sentences is not an instant. The generous read timeout is on the
# service's account, not the user's: a slow explanation should not feel like a hang, and
# the cost of waiting is borne by whoever asked for it.
CONNECT_TIMEOUT = 5.0


class Explainer(Protocol):
    """Anything that can describe a score. Structural, like ``PackageRegistry``."""

    async def explain(self, outcome: AnalysisOutcome) -> Explanation: ...


class RemoteExplainer:
    """Asks the PackSafe service to explain a score.

    Named for what it is - an HTTP call to a service this project also owns - so that a
    future local or in-process implementation can sit beside it without pretending to be
    remote.
    """

    name = "remote"

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or _service_url()).rstrip("/")
        self.timeout = timeout
        # Optional shared secret. The endpoint is an unauthenticated oracle by default -
        # anyone can ask it to describe an arbitrary score - so a deployment that exposes
        # it publicly should set this and enforce it server-side.
        self.token = token
        self._client = client

    async def explain(self, outcome: AnalysisOutcome) -> Explanation:
        """Posts the finished score and returns the prose describing it."""
        request = build_explain_request(outcome)
        payload = request.to_payload()

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        logger.info(
            "explanation request | url=%s package=%s score=%.2f",
            self.base_url,
            request.package_name,
            request.final_score,
        )

        client = self._client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=CONNECT_TIMEOUT, read=self.timeout, write=10.0, pool=10.0
            )
        )
        async with client:
            response = await client.post(
                f"{self.base_url}/api/explain/", json=payload, headers=headers
            )

        if response.status_code != 200:
            logger.warning(
                "explanation service returned status=%d | %s",
                response.status_code,
                response.text[:200],
            )
            raise ExplainerError(f"explanation service returned HTTP {response.status_code}")

        body = response.json()
        return Explanation(
            # Read back from the *request*, not the body: the service echoes these from
            # what it was sent, so this is the score we actually computed. Taking them
            # from the response would mean trusting a network hop to have kept them
            # straight, and the whole point of printing them next to the prose is that
            # they are ours.
            package_name=request.package_name,
            final_score=request.final_score,
            decision=request.decision,
            explanation=body["explanation"],
            provider=body.get("provider", "unknown"),
            model=body.get("model", "unknown"),
        )


class ExplainerError(Exception):
    """The explanation could not be produced. Never fatal to the analysis."""


def _service_url() -> str:
    """Resolves the PackSafe service URL.

    Reads the environment here rather than relying on ``settings``, because ``settings`` is
    a module-level singleton evaluated at import: a value exported after startup - which is
    normal when the CLI is invoked as a library, and what a test does - would be ignored.
    ``settings`` remains the default.
    """
    return os.getenv(ENV_URL) or settings.EXPLAIN_API_URL


def build_explainer(base_url: str | None = None) -> Explainer:
    """Builds the explainer the CLI will use, from the environment."""
    timeout = os.getenv(ENV_TIMEOUT)
    return RemoteExplainer(
        base_url,
        timeout=float(timeout) if timeout else DEFAULT_TIMEOUT,
        token=os.getenv(ENV_TOKEN),
    )


def request_explanation(console: Console, outcome: AnalysisOutcome) -> Explanation | None:
    """Fetches an explanation, or returns ``None`` for any reason at all.

    Every failure lands here rather than at the call site, because the call site has
    nothing useful to do with one. ``analyze`` has already printed a complete report and
    decided its exit code; the analysis is finished, and a missing paragraph cannot
    un-finish it. Raising would mean a user who asked for extra detail could lose the
    result they already had - the worst possible failure mode for a security tool.

    ``--explain`` is also the one flag here that can block, so the wait is announced
    before it starts rather than leaving a silent pause that looks like a hang.
    """
    explainer = build_explainer()

    try:
        with console.status("[bold cyan]Asking for an explanation[/bold cyan]...", spinner="dots"):
            return asyncio.run(explainer.explain(outcome))
    except ExplainerError as e:
        # The service answered, but with a failure: 4xx from our own auth, 5xx from it, or
        # 502 because it has no model provider configured. The status is logged; the reader
        # gets the cause in words rather than a code they would have to look up.
        logger.warning("explanation service returned an error: %s", e)
        console.print(
            _unavailable_note("the explanation service could not produce one (check its logs)")
        )
        return None
    except httpx.HTTPError as e:
        logger.warning("explanation transport error: %s", e)
        console.print(
            _unavailable_note(
                f"the explanation service was unreachable ({type(e).__name__})"
            )
        )
        return None
    except Exception as e:
        # Anything unexpected is logged with its traceback and reported as unavailable.
        # A bug in rendering must not cost the reader their score. See the docstring for
        # why this deliberately catches everything.
        logger.exception("explanation failed with an unhandled error: %s", type(e).__name__)
        console.print(_unavailable_note("the explanation could not be generated"))
        return None


def explain_and_render(console: Console, outcome: AnalysisOutcome) -> None:
    """The whole feature: get a paragraph, print it, or say why there isn't one."""
    explanation = request_explanation(console, outcome)

    if explanation is None:
        # The note is already printed. Nothing else to do - the report above stands.
        return

    render_explanation(console, outcome, explanation)


def _unavailable_note(reason: str) -> str:
    """The one-line explanation for why there is no explanation.

    Names the cause without dumping a traceback, and points at the log for detail, which
    is where a user debugging this needs to look anyway.
    """
    return (
        f"  [bright_black]--explain: {reason}. The score above is unaffected; "
        f"see the log for detail.[/bright_black]"
    )