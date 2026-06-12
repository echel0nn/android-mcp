"""In-process LRU cache for android-mcp's heavyweight static-analysis tools.

Several actions in android-mcp (``classify_behavior``,
``verify_capabilities``, ``capa_scan``, ``mobsf_static_scan``,
``jadx_decompile``, ``apktool_decode``, ``androguard_summary``) are
deterministic functions of the input APK plus a small set of named
options. They take minutes to hours on a 30k+ class APK; running the
same call N times in parallel (one per panel branch in a
multi-persona deliberation) wastes N×T of CPU.

This module gives the HTTP dispatcher (:mod:`android_mcp.http_api`) a
single LRU surface keyed on the APK's content hash + action name +
normalized non-noise arg fingerprint. First caller pays the cost;
concurrent callers wait on the SAME inflight future (no thundering
herd); future callers within the TTL get the cached result instantly.

Design notes:

* Per-process, not cross-process. AILA's worker pool has 3 vr workers
  by default; each maintains its own cache. Cache-miss work is paid
  once per worker but never duplicated within a worker.
* Inflight-future dedup. Two POSTs that hash to the same key while
  the first is still running both await the same future. Critical
  for the panel-deliberation scenario where 6 branches fire the
  same call at sub-second intervals.
* TTL is generous: 6 hours by default. The same APK rarely
  re-uploaded by the operator within that window; if it is, the
  worst case is one stale answer per worker per TTL.
* Eviction is "least-recently-set" (insertion order under Python's
  dict): when the cache exceeds ``maxsize`` (default 64 entries),
  the oldest get dropped. 64 entries × ~5 MB per heavy result =
  ~320 MB peak in-process; matches the AILA worker RAM budget.

Cache key components:

  - action: the named tool (``classify_behavior``, ``capa_scan``, ...)
  - apk_sha256: extracted from the ``apk_path`` kwarg. AILA's bridge
    uploads APKs to a content-addressed shared dir, so the basename
    IS the hex SHA-256. If the kwarg lookup fails (operator passes a
    non-content-addressed path), the action is treated as
    non-cacheable and runs normally.
  - args_fingerprint: stable-ordered JSON of the non-apk-path kwargs.
    None of the cacheable tools today carry options outside the path,
    but the fingerprint is included so a future option-bearing action
    (e.g. ``mobsf_static_scan(profile='quick'|'full')``) caches
    correctly per-option.

Diagnostics:

* :func:`stats` returns ``{hits, misses, inflight_waits, evictions,
  entries, by_action}`` for the ``/runtime`` endpoint.
* :func:`invalidate_all` clears the cache (operator escape hatch on
  the same endpoint).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

_log = logging.getLogger(__name__)

__all__ = [
    "CACHEABLE_ACTIONS",
    "cache_dispatch",
    "invalidate_all",
    "stats",
]


# Heavy static-analysis tools. Picked by hand from server.py's tool
# registry; ADD a new tool here when it (a) takes >10 s on a 30k-class
# APK and (b) is a pure function of the APK + named args (no live
# device, no time-of-day-dependent network state).
CACHEABLE_ACTIONS: frozenset[str] = frozenset(
    {
        "classify_behavior",
        "verify_capabilities",
        "capa_scan",
        "androguard_summary",
        "mobsf_static_scan",
        "jadx_decompile",
        "apktool_decode",
        "yara_decompiled_scan",
        "lief_so_inspect",
    },
)

# Maximum entries. 64 × ~5 MB heavy result = ~320 MB peak in-process.
# Override via env for operator workstation tuning.
_MAX_ENTRIES: int = int(os.environ.get("ANDROID_MCP_CACHE_MAXSIZE", "64"))

# Time-to-live in seconds. 6 hours default — the same APK rarely
# re-uploaded by the operator within that window. Set to 0 to disable.
_TTL_S: float = float(os.environ.get("ANDROID_MCP_CACHE_TTL_S", "21600"))

# Regex for hex-SHA-256 inside the apk_path basename. AILA's bridge
# uploads to a shared dir where the filename IS the SHA-256.
_SHA256_RE = re.compile(r"\b([0-9a-f]{64})\b", re.IGNORECASE)


@dataclass(slots=True)
class _Entry:
    value: Any
    stored_at: float
    action: str

    def expired(self, now: float) -> bool:
        if _TTL_S <= 0:
            return False
        return (now - self.stored_at) > _TTL_S


# Cache itself — OrderedDict for LRU semantics. Each cache key maps
# to either an :class:`_Entry` (cached result) OR an
# ``asyncio.Future`` (work in progress).
_CACHE: OrderedDict[str, _Entry | asyncio.Future[Any]] = OrderedDict()

# Hit / miss counters for /runtime.
_STATS: dict[str, int] = {
    "hits": 0,
    "misses": 0,
    "inflight_waits": 0,
    "evictions": 0,
    "expired": 0,
    "non_cacheable_dispatched": 0,
}
_BY_ACTION: dict[str, dict[str, int]] = {}


def _bump_action(action: str, key: str) -> None:
    bucket = _BY_ACTION.setdefault(action, {"hits": 0, "misses": 0, "inflight_waits": 0})
    bucket[key] += 1


def _apk_sha256_from_path(p: str | None) -> str | None:
    if not isinstance(p, str) or not p:
        return None
    m = _SHA256_RE.search(p)
    return m.group(1).lower() if m else None


def _args_fingerprint(kwargs: dict[str, Any]) -> str:
    """Stable-ordered JSON of the non-apk-path kwargs.

    Drops the path itself (it's already in the key via the sha256)
    and sorts keys so two callers with identical option sets hash
    to the same fingerprint regardless of dict ordering.
    """
    fp = {k: v for k, v in kwargs.items() if k != "apk_path"}
    try:
        return json.dumps(fp, sort_keys=True, default=str)
    except (TypeError, ValueError):
        # Non-JSON-serializable nested object — fall back to repr.
        return repr(sorted(fp.items()))


def _make_key(action: str, apk_sha256: str, kwargs: dict[str, Any]) -> str:
    fp = _args_fingerprint(kwargs)
    # SHA-256-of-fingerprint keeps the key bounded length-wise.
    fp_hash = hashlib.sha256(fp.encode("utf-8")).hexdigest()[:16]
    return f"{action}:{apk_sha256}:{fp_hash}"


def _evict_if_oversize() -> None:
    while len(_CACHE) > _MAX_ENTRIES:
        _CACHE.popitem(last=False)
        _STATS["evictions"] += 1


async def cache_dispatch(
    action: str,
    kwargs: dict[str, Any],
    invoker: Callable[[], Awaitable[Any]],
) -> Any:
    """Cache-aware wrapper around the underlying tool invoker.

    Three paths:

      1. Action not in :data:`CACHEABLE_ACTIONS` OR no APK sha256 in
         args: bypass the cache, call ``invoker`` directly.
      2. Cache hit (and not expired): return the cached value.
      3. Cache miss: store an inflight future in the cache; concurrent
         callers in the same window await the same future. The first
         caller awaits ``invoker()`` itself.

    ``invoker`` is a zero-arg async callable so the cache can decide
    whether to await it. The dispatcher in :mod:`android_mcp.http_api`
    passes ``lambda: run_tool(name, fn, payload)``.
    """
    if action not in CACHEABLE_ACTIONS:
        _STATS["non_cacheable_dispatched"] += 1
        return await invoker()

    apk_sha256 = _apk_sha256_from_path(kwargs.get("apk_path"))
    if apk_sha256 is None:
        # Non-content-addressed path — operator's own working dir
        # OR a future tool variant. Bypass cache (correctness over
        # speed).
        _STATS["non_cacheable_dispatched"] += 1
        return await invoker()

    key = _make_key(action, apk_sha256, kwargs)
    now = time.monotonic()

    entry = _CACHE.get(key)
    if isinstance(entry, _Entry):
        if entry.expired(now):
            _CACHE.pop(key, None)
            _STATS["expired"] += 1
        else:
            _STATS["hits"] += 1
            _bump_action(action, "hits")
            _CACHE.move_to_end(key)
            return entry.value

    if isinstance(entry, asyncio.Future):
        # Inflight; first caller is mid-invoker. Subsequent callers
        # await the same future — no thundering herd.
        _STATS["inflight_waits"] += 1
        _bump_action(action, "inflight_waits")
        return await entry
    # Miss — store inflight future BEFORE awaiting so a parallel
    # call at the next event-loop tick sees the future and joins it.
    loop = asyncio.get_running_loop()
    future: asyncio.Future[Any] = loop.create_future()
    _CACHE[key] = future
    _STATS["misses"] += 1
    _bump_action(action, "misses")
    try:
        value = await invoker()
    except Exception as exc:
        # On exception: drop the inflight future (don't cache failures)
        # and propagate to all waiters via the future + raise to the
        # current caller. Retrieve the exception from the future
        # afterwards to silence asyncio's "Future exception was never
        # retrieved" warning when no concurrent waiter joined.
        if not future.done():
            future.set_exception(exc)
        try:
            future.exception()
        except (asyncio.CancelledError, asyncio.InvalidStateError):
            pass
        _CACHE.pop(key, None)
        raise
    # On success: convert the inflight future into an _Entry, then
    # resolve the future so any concurrent waiter that joined it
    # gets the value.
    if not future.done():
        future.set_result(value)
    _CACHE[key] = _Entry(value=value, stored_at=now, action=action)
    _evict_if_oversize()
    return value


def stats() -> dict[str, Any]:
    """Return cache stats for /runtime diagnostics."""
    return {
        **_STATS,
        "entries": sum(1 for v in _CACHE.values() if isinstance(v, _Entry)),
        "inflight": sum(1 for v in _CACHE.values() if isinstance(v, asyncio.Future)),
        "maxsize": _MAX_ENTRIES,
        "ttl_s": _TTL_S,
        "by_action": {k: dict(v) for k, v in _BY_ACTION.items()},
    }


def invalidate_all() -> int:
    """Drop every cached entry. Returns count of entries evicted.

    Inflight futures are left alone — cancelling them mid-flight would
    raise CancelledError for every concurrent waiter which is worse
    than letting them resolve and being dropped on the next call.
    """
    evicted = 0
    for k in list(_CACHE.keys()):
        v = _CACHE[k]
        if isinstance(v, _Entry):
            _CACHE.pop(k, None)
            evicted += 1
    return evicted
