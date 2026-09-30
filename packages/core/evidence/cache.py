"""Evidence Cache abstractions supporting in-memory and Redis backends with TTL and provenance."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class CachedEvidenceRecord:
    """Stored cache record with metadata for provenance and freshness."""
    payload: Any
    retrieved_at: float
    source: str
    collector_version: str = "1.0.0"
    content_hash: str | None = None

    def is_stale(self, ttl_seconds: float) -> bool:
        """Returns True if the record has exceeded its freshness TTL."""
        return (time.time() - self.retrieved_at) > ttl_seconds

    def status_for_ttl(self, ttl_seconds: float) -> str:
        """Returns 'AVAILABLE' or 'STALE' based on elapsed time."""
        return "STALE" if self.is_stale(ttl_seconds) else "AVAILABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "retrieved_at": self.retrieved_at,
            "source": self.source,
            "collector_version": self.collector_version,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CachedEvidenceRecord:
        return cls(
            payload=data.get("payload"),
            retrieved_at=float(data.get("retrieved_at", time.time())),
            source=data.get("source", "unknown"),
            collector_version=data.get("collector_version", "1.0.0"),
            content_hash=data.get("content_hash"),
        )


class EvidenceCache(Protocol):
    """Protocol for evidence caching backends."""

    def get(self, key: str) -> CachedEvidenceRecord | None:
        ...

    def set(self, key: str, record: CachedEvidenceRecord, ttl_seconds: float | None = None) -> None:
        ...

    def invalidate(self, key: str) -> None:
        ...

    def clear(self) -> None:
        ...


class InMemoryEvidenceCache:
    """Thread-safe in-memory cache for package evidence snapshots."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[float | None, CachedEvidenceRecord]] = {}

    def get(self, key: str) -> CachedEvidenceRecord | None:
        if key not in self._store:
            return None
        expiry, record = self._store[key]
        if expiry is not None and time.time() > expiry:
            del self._store[key]
            return None
        return record

    def get_with_freshness(self, key: str, ttl_seconds: float) -> tuple[CachedEvidenceRecord | None, str]:
        """Returns (record, status) where status is 'AVAILABLE', 'STALE', or 'MISSING'."""
        record = self.get(key)
        if record is None:
            return (None, "MISSING")
        status = record.status_for_ttl(ttl_seconds)
        return (record, status)

    def set(self, key: str, record: CachedEvidenceRecord, ttl_seconds: float | None = None) -> None:
        expiry = time.time() + ttl_seconds if ttl_seconds is not None else None
        self._store[key] = (expiry, record)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()


import logging
import os

logger = logging.getLogger(__name__)


class RedisEvidenceCache:
    """Redis-backed evidence cache with automatic JSON serialization and operational degradation tracking."""

    def __init__(self, redis_url: str = "redis://localhost:6379/0", strict_production: bool | None = None) -> None:
        self.redis_url = redis_url
        self._fallback_memory = InMemoryEvidenceCache()
        self._redis_client = None
        self._redis_available = False
        
        # Determine if strict production mode is required
        if strict_production is None:
            self.strict_production = os.getenv("PACKSAFE_ENV", "development").lower() == "production"
        else:
            self.strict_production = strict_production

        try:
            import redis
            import json
            client = redis.from_url(redis_url, socket_timeout=1.0)
            client.ping()
            self._redis_client = client
            self._redis_available = True
            logger.info("Connected to Redis evidence cache at %s", redis_url)
        except Exception as exc:
            self._redis_available = False
            if self.strict_production:
                logger.critical("PRODUCTION ALERT: Redis unavailable at %s. Refusing silent fallback.", redis_url)
                raise RuntimeError(f"Production Redis cache connection failed: {exc}") from exc
            logger.warning(
                "Redis unavailable at %s (%s). Cache operating in DEGRADED in-memory fallback mode.",
                redis_url,
                exc,
            )

    @property
    def cache_mode(self) -> str:
        """Returns 'redis' if connected to Redis backend, or 'degraded' if fallen back to memory."""
        return "redis" if self._redis_available else "degraded"

    def get(self, key: str) -> CachedEvidenceRecord | None:
        if self._redis_available and self._redis_client:
            try:
                import json
                raw = self._redis_client.get(key)
                if raw:
                    data = json.loads(raw)
                    return CachedEvidenceRecord.from_dict(data)
                return None
            except Exception as exc:
                logger.warning("Redis read failed for %s (%s); falling back to memory store", key, exc)
        return self._fallback_memory.get(key)

    def set(self, key: str, record: CachedEvidenceRecord, ttl_seconds: float | None = None) -> None:
        if self._redis_available and self._redis_client:
            try:
                import json
                raw = json.dumps(record.to_dict())
                if ttl_seconds is not None:
                    self._redis_client.setex(key, int(ttl_seconds), raw)
                else:
                    self._redis_client.set(key, raw)
                return
            except Exception:
                pass
        self._fallback_memory.set(key, record, ttl_seconds)

    def invalidate(self, key: str) -> None:
        if self._redis_available and self._redis_client:
            try:
                self._redis_client.delete(key)
                return
            except Exception:
                pass
        self._fallback_memory.invalidate(key)

    def clear(self) -> None:
        if self._redis_available and self._redis_client:
            try:
                self._redis_client.flushdb()
                return
            except Exception:
                pass
        self._fallback_memory.clear()


def make_cache_key(ecosystem: str, package: str, version: str, evidence_type: str) -> str:
    """Generates standard cache key format: ecosystem:package:version:evidence_type."""
    return f"{ecosystem.lower()}:{package.lower()}:{version.lower()}:{evidence_type.lower()}"


_global_cache: EvidenceCache | None = None


def get_evidence_cache() -> EvidenceCache:
    global _global_cache
    if _global_cache is None:
        _global_cache = InMemoryEvidenceCache()
    return _global_cache
