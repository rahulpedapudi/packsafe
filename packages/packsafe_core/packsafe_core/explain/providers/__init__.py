"""LLM adapters, one per wire format.

Not imported eagerly by the package: :mod:`packsafe_core.explain.registry` imports a
builder lazily so a deployment pays only for the provider it actually uses. Import the
module for the provider you want directly.
"""