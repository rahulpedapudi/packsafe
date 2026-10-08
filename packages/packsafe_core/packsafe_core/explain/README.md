# The explanation layer

Turns an already-computed `ScoreResult` into prose, using an LLM. Nothing in this
package can change a score.

## The rule

The score is computed by the deterministic engine, locally, and arrives here finished.
This layer only describes it. It never re-scores, never overrides a decision, and never
feeds back into `scoring/`. That separation is the point: an explanation can be wrong,
vague, or unavailable without ever making a verdict wrong.

## Layout

| Module | Responsibility |
| --- | --- |
| `contract.py` | The wire format. Built by the client, parsed by the service. |
| `projection.py` | `AnalysisOutcome` → `ExplainRequest`. The redaction chokepoint. |
| `provider.py` | `LLMProvider` Protocol, plus `CompletionRequest` / `Completion`. |
| `providers/` | One adapter per wire format. Imported lazily. |
| `prompt.py` | The prompt. Identical for every provider. |
| `registry.py` | Configuration → provider, plus the `explain()` call. |

## Where the API key goes

**On the server, never in the CLI.** This is the whole reason `--explain` is an HTTP call
to a service this project owns rather than a call into a model SDK from the CLI.

```
# on the machine running the backend
export PACKSAFE_LLM_PROVIDER=openai
export PACKSAFE_LLM_API_KEY=sk-...        # <- the only place this ever appears
export PACKSAFE_LLM_MODEL=gpt-4o-mini     # optional
export PACKSAFE_LLM_BASE_URL=...         # optional; any OpenAI-compatible endpoint
export PACKSAFE_LLM_TIMEOUT=30           # optional; seconds

uvicorn app.main:app --port 8000
```

A user installs the CLI and gets explanations without ever handling a provider
credential, and you can change models without cutting a CLI release.

The CLI has its own, entirely separate settings:

```
PACKSAFE_EXPLAIN_URL     which PackSafe service to ask (default: http://localhost:8000)
PACKSAFE_EXPLAIN_TOKEN   optional shared secret, sent as a bearer token
PACKSAFE_EXPLAIN_TIMEOUT seconds to wait for the prose (default: 60)
```

`PACKSAFE_EXPLAIN_TOKEN` is not a provider key. It authenticates the caller to *your*
service, which is otherwise an open endpoint - see the trust section below.

## Configuration

```
PACKSAFE_LLM_PROVIDER   openai | anthropic | gemini   (default: openai)
PACKSAFE_LLM_API_KEY    required
PACKSAFE_LLM_MODEL      optional; defaults per vendor, see providers/openai_compat.py
PACKSAFE_LLM_BASE_URL   optional; any OpenAI-compatible endpoint
PACKSAFE_LLM_TIMEOUT    optional; seconds, default 30
```

`openai` is the useful one. The chat-completions format is close to a lingua franca, so
Groq, Together, DeepSeek, Fireworks, OpenRouter, Mistral, xAI, LM Studio, vLLM, llama.cpp
and Ollama's compatibility endpoint are all reached by changing `PACKSAFE_LLM_BASE_URL`
and the key — including fully self-hosted models, which need nothing else.

Adding a genuinely new wire format means one file in `providers/` and one entry in
`registry.BUILDERS`. Adding a vendor that already speaks an implemented format requires
no code at all.

## What the prompt does and does not receive

Only derived numbers and PackSafe-authored labels. `Finding.evidence` — a code snippet
copied verbatim out of the analyzed archive — is withheld, as is every gate's
`evidence_ids` (which embed archive file paths).

That is not primarily a privacy measure. A package author controls every byte of their
own sdist, so author-controlled text placed in a prompt becomes an instruction aimed at
the person reading the model's output. Three layers contain it:

1. The contract cannot carry archive text at all (see `FindingExplain`).
2. The payload is `json.dumps`-serialized, so a newline in a hostile string becomes a
   literal `\n` escape and cannot produce a fence marker on its own line.
3. The prompt fences the data block, describes it as untrusted, and appends the real task
   last so it is the final thing the model reads.

None of this makes injection impossible — a sufficiently determined package can still put
attacker-influenced words in a title. It makes the payload structurally hard to subvert,
and the system prompt asks the model to report attempted manipulation as a finding in its
own right.

## Trust and failure

The service is an unauthenticated "make anything sound safe" oracle: anyone can post an
arbitrary `final_score` and receive a confident paragraph. Two consequences, both
enforced in code:

- The response echoes `package_name`, `final_score` and `decision` **from the request**,
  never from the model. A caller rendering them beside the prose can see whether the two
  agree, which is what makes it safe to display model output at all.
- Provider failures surface as `502` with no provider detail. An upstream error body can
  quote the prompt or a key fragment; that belongs in the log, not in a response.

Authenticate and rate-limit this route before exposing it publicly. The client side of that
is `PACKSAFE_EXPLAIN_TOKEN`, which `RemoteExplainer` sends as a bearer token.

## On the CLI side

`packsafe_cli/explain.py` holds a single guarantee: **an explanation cannot affect a
verdict.** `request_explanation` returns `None` for every possible failure - transport
error, bad status, non-JSON body, missing field, or a bug in our own renderer - and the
`--explain` call sits outside `run_analysis` in both `analyze` and `inspect`, after the
report has been printed. There is no path by which losing a paragraph costs the reader
their score.

The returned `Explanation` takes its `package_name`, `final_score` and `decision` from the
*request*, never from the response body, so the values printed beside the prose are the
ones the local engine computed.

Rendering strips terminal control characters from model output. Rich escapes `[bold]`-style
markup, so restyling is already impossible - but a raw ANSI escape is not markup, it is an
instruction to the terminal, and Rich passes it through. Untreated, model output could
clear the screen or set the window title. See `display/explain.py::_strip_control`.

## Tests

```
packages/packsafe_core/tests/unit/explain/   contract, prompt, projection, adapters
packages/backend/tests/test_explain_api.py   route, against a stubbed provider
packages/packsafe_cli/tests/test_explain.py  client, degradation, safe rendering
```

`test_projection.py::TestRedaction` and `test_prompt.py::TestInjectionResistance` are the
ones to read first - they encode the prompt-side security properties as executable
assertions. `test_explain.py::TestFailureNeverPropagates` encodes the client-side one.