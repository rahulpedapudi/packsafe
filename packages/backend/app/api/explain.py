"""``POST /api/explain`` - describes a computed PackSafe score in plain language.

Two things this endpoint is not, both deliberate:

**It is not a scorer.** The score arrives finished, from a client that ran the
deterministic engine locally, and nothing here recomputes or adjusts it. That keeps the
score auditable and keeps the LLM out of the trust path - a model that can move a number
cannot be checked against a formula.

**It is not trusted with the client's claims.** Anyone can post an arbitrary
``final_score`` and get back a confident paragraph. The response therefore echoes the
package, score and decision it was given so the caller can display them beside the prose,
and a caller rendering that prose alongside its own score can see at a glance whether the
two agree. Rate-limiting and authentication belong in front of this route before it is
exposed publicly.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from packsafe_core.explain import ExplainError

from ..schemas.explain import ExplainRequestBody, ExplanationResponse
from ..services import explain_service

logger = logging.getLogger(__name__)

explain_router = APIRouter()


@explain_router.post("/", response_model=ExplanationResponse)
async def explain(body: ExplainRequestBody) -> ExplanationResponse:
    """Returns a natural-language explanation of an already-computed score."""
    try:
        return await explain_service.explain_score(body)
    except ValueError as e:
        # A body that does not parse. 422 with the field name is more useful to the
        # client than a generic 500, and the message carries no prompt content.
        logger.info("explain request rejected | %s", e)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)) from e
    except ExplainError as e:
        # The provider is unreachable, unauthenticated, rate-limited, or refused. The
        # client's analysis is unaffected - it already has its score - so this is a 502
        # the caller should degrade past, not a failure of the request itself.
        logger.warning("explain upstream failure | %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="explanation provider unavailable"
        ) from e