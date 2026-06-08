"""Async-first runtime primitives for the HTTP tool transport.

Adapted from audit-mcp's ``async_runtime.py``. The job is identical:
give the FastAPI tool dispatcher per-tool semaphores, in-flight dedup,
wall-clock timeouts, and a resized thread pool so the
single-dispatch-route in :mod:`android_mcp.http_api` does not become
the kind of bottleneck the original sync handler was on audit-mcp.

One structural difference from audit-mcp: every tool handler currently
registered by ``android_mcp.tools.*`` is ``async def``. Rather than
ship two parallel entry points (``run_tool`` for sync + a separate
``_run_async_tool`` for awaitables, the way audit-mcp evolved its
runtime to retrofit async support), :func:`run_tool` here auto-detects
the callable shape and dispatches:

  * async function → awaited directly under the same semaphore + dedup
    + timeout discipline.
  * sync function → offloaded to anyio's worker thread pool, same
    contract as audit-mcp.

That keeps callers (``http_api.invoke_tool``) honest with a single
entry point that does not care about callable colour. When a future
android-mcp tool ships as plain ``def``, it slots in without any
runtime-layer rewrite.

Knobs:

  * ``ANDROID_MCP_THREAD_POOL_LIMIT`` — anyio worker-thread pool size.
  * ``ANDROID_MCP_TOOL_CAP_<TOOLNAME_UPPER>`` — per-tool concurrent
    call cap. Overrides :data:`DEFAULT_TOOL_CAPS`.
  * ``ANDROID_MCP_TIMEOUT_<TOOLNAME_UPPER>`` — per-tool wall-clock
    timeout in seconds. Overrides :data:`DEFAULT_TOOL_TIMEOUTS_S`.

Defaults target a single-worker Windows host running the mobile
toolchain (apktool / jadx subprocesses, MobSF REST, androguard
in-process parses). The heavy three (``apktool_decode``,
``jadx_decompile``, ``mobsf_scan``) get explicit lower caps and higher
timeouts than the ``__default__`` because they each soak disk +
memory + minutes-long wall-clock and would otherwise starve cheaper
calls behind a single thread-pool budget.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

import anyio.to_thread

__all__ = [
    "InFlightDedup",
    "ToolSemaphores",
    "configure_thread_pool",
    "run_tool",
    "runtime_stats",
    "reset_runtime",
    "DEFAULT_TOOL_CAPS",
    "DEFAULT_TOOL_TIMEOUTS_S",
]

_log = logging.getLogger(__name__)


# --- per-tool concurrency caps ------------------------------------------
# The heavy three (apktool, jadx, MobSF) each occupy a worker for
# minutes when they hit a non-trivial APK; capping them at 2 keeps the
# pool from collapsing under sibling investigation branches firing the
# same scans in parallel. Everything else inherits the ``__default__``.
# Operators override via ``ANDROID_MCP_TOOL_CAP_<TOOLNAME>``.
DEFAULT_TOOL_CAPS: dict[str, int] = {
    "apktool_decode":  2,
    "jadx_decompile":  2,
    "mobsf_scan":      2,
    "__default__":     8,
}


# --- per-tool wall-clock timeouts ---------------------------------------
# A timeout fires from the perspective of the async caller — the
# underlying worker thread cannot be force-killed (Python has no thread
# kill primitive), so the work continues to completion in the
# background and its result is discarded. Repeated timeouts on the
# same tool indicate either (a) a truly stuck call deserving operator
# investigation, or (b) too-low a cap.
DEFAULT_TOOL_TIMEOUTS_S: dict[str, float] = {
    "apktool_decode":  300.0,
    "jadx_decompile":  900.0,
    "mobsf_scan":     1800.0,
    "__default__":     120.0,
}


def _canonical_kwargs(kwargs: dict[str, Any]) -> str:
    """JSON-canonical kwargs for dedup keying.

    Sorting keys + default ``repr`` means callers that pass the same
    logical arg set in different dict orderings still collide on the
    same dedup key.
    """
    try:
        return json.dumps(kwargs, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(sorted(kwargs.items()))


# ----------------------------------------------------------------------
# InFlightDedup
# ----------------------------------------------------------------------


class InFlightDedup:
    """Coalesce concurrent identical tool calls onto one in-flight future.

    Keyed by ``(tool_name, sha256(canonical_kwargs))``. Hits cap latency
    of waiters to the source-call's latency; misses degrade to a normal
    function call. The dedup is **strict equality on the kwargs JSON**
    — two callers with semantically-equivalent but lexically-different
    kwargs (e.g. ``rescan=None`` vs missing ``rescan`` key) DO NOT
    collide and each pays their own cost. That trade-off is deliberate:
    false positives in the cache key are far worse than missing some
    dedup wins.

    Entries auto-evict the moment the source call resolves; this is
    a "while-in-flight only" cache, not a result memoizer. Downstream
    tools may already have their own caches (MobSF DB, jadx output
    dir) — we do not try to replicate that here.
    """

    def __init__(self) -> None:
        self._inflight: dict[str, asyncio.Future[Any]] = {}
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def key_for(tool_name: str, kwargs: dict[str, Any]) -> str:
        canonical = _canonical_kwargs(kwargs)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return f"{tool_name}:{digest}"

    async def get_or_create(
        self,
        key: str,
        producer: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Run ``producer()`` once for ``key``; wait on the same future
        for concurrent callers with the same key."""
        async with self._lock:
            existing = self._inflight.get(key)
            if existing is not None:
                self._hits += 1
                fut = existing
            else:
                self._misses += 1
                loop = asyncio.get_running_loop()
                fut = loop.create_future()
                self._inflight[key] = fut

        if existing is not None:
            return await fut

        try:
            result = await producer()
        except BaseException as exc:  # noqa: BLE001 — propagate to all waiters
            async with self._lock:
                self._inflight.pop(key, None)
            if not fut.done():
                fut.set_exception(exc)
            raise

        async with self._lock:
            self._inflight.pop(key, None)
        if not fut.done():
            fut.set_result(result)
        return result

    def stats(self) -> dict[str, int]:
        return {
            "inflight": len(self._inflight),
            "hits": self._hits,
            "misses": self._misses,
        }


# ----------------------------------------------------------------------
# ToolSemaphores
# ----------------------------------------------------------------------


class ToolSemaphores:
    """Per-tool concurrency limiter.

    Owns one :class:`asyncio.Semaphore` per tool name. Acquire the
    semaphore BEFORE submitting work to the thread pool (or BEFORE
    awaiting an async tool); this caps the number of pool slots a
    single tool can consume and prevents one tool from starving the
    others.

    Caps come from :data:`DEFAULT_TOOL_CAPS`, overridable via env var
    ``ANDROID_MCP_TOOL_CAP_<TOOLNAME_UPPER>``. Unknown tools get the
    ``__default__`` cap.
    """

    def __init__(self, caps: dict[str, int] | None = None) -> None:
        merged = dict(DEFAULT_TOOL_CAPS)
        if caps:
            merged.update(caps)
        for tool_name, _default_cap in list(merged.items()):
            env_key = f"ANDROID_MCP_TOOL_CAP_{tool_name.upper()}"
            override = os.environ.get(env_key)
            if override:
                try:
                    merged[tool_name] = max(1, int(override))
                except ValueError:
                    _log.warning(
                        "ignoring non-integer env override %s=%r",
                        env_key, override,
                    )
        self._caps = merged
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def for_tool(self, tool_name: str) -> asyncio.Semaphore:
        sem = self._semaphores.get(tool_name)
        if sem is None:
            cap = self._caps.get(tool_name, self._caps.get("__default__", 8))
            sem = asyncio.Semaphore(cap)
            self._semaphores[tool_name] = sem
        return sem

    def cap_for(self, tool_name: str) -> int:
        return self._caps.get(tool_name, self._caps.get("__default__", 8))

    def stats(self) -> dict[str, Any]:
        """Snapshot of ``{tool_name: {cap, available}}``.

        ``available`` reflects how many slots are NOT currently held —
        a cheap proxy for "is this tool the bottleneck right now".
        Only tools that have been observed (semaphore lazily
        instantiated) appear here; that keeps the snapshot small for
        ops dashboards.
        """
        out: dict[str, Any] = {}
        for tool_name, sem in self._semaphores.items():
            cap = self._caps.get(tool_name, self._caps.get("__default__", 8))
            # asyncio.Semaphore._value is internal but stable — public
            # API has no introspection.
            available = getattr(sem, "_value", -1)
            out[tool_name] = {"cap": cap, "available": available}
        return out


# ----------------------------------------------------------------------
# Threadpool sizing
# ----------------------------------------------------------------------


def configure_thread_pool(limit: int | None = None) -> int:
    """Resize the anyio default thread limiter.

    FastAPI/Starlette dispatch sync handlers through anyio's
    ``current_default_thread_limiter()``. The default is 40 — fine for
    short I/O-bound work, too small for our mix where a single
    ``mobsf_scan`` can occupy a slot for half an hour.

    Resolves order:
      1. Explicit ``limit`` argument.
      2. Env ``ANDROID_MCP_THREAD_POOL_LIMIT``.
      3. Fallback: 64.

    Returns the limit that was applied.
    """
    if limit is None:
        env = os.environ.get("ANDROID_MCP_THREAD_POOL_LIMIT")
        limit = int(env) if env else 64
    limit = max(8, limit)  # never go below 8 — risk of trivial starvation
    limiter = anyio.to_thread.current_default_thread_limiter()
    limiter.total_tokens = limit
    return limit


# ----------------------------------------------------------------------
# run_tool — the unified async entry point
# ----------------------------------------------------------------------


# Module-level singletons. Wire-up happens lazily on first
# :func:`run_tool` / :func:`runtime_stats` call so tests can substitute
# their own instances via :func:`reset_runtime`.
_DEDUP: InFlightDedup | None = None
_SEMS: ToolSemaphores | None = None


def reset_runtime() -> None:
    """Reset module-level dedup + semaphore state. For tests."""
    global _DEDUP, _SEMS
    _DEDUP = None
    _SEMS = None


def _ensure_runtime() -> tuple[InFlightDedup, ToolSemaphores]:
    global _DEDUP, _SEMS
    if _DEDUP is None:
        _DEDUP = InFlightDedup()
    if _SEMS is None:
        _SEMS = ToolSemaphores()
    return _DEDUP, _SEMS


def _timeout_for(tool_name: str) -> float:
    env_key = f"ANDROID_MCP_TIMEOUT_{tool_name.upper()}"
    override = os.environ.get(env_key)
    if override:
        try:
            return max(1.0, float(override))
        except ValueError:
            _log.warning(
                "ignoring non-numeric env override %s=%r",
                env_key, override,
            )
    if tool_name in DEFAULT_TOOL_TIMEOUTS_S:
        return DEFAULT_TOOL_TIMEOUTS_S[tool_name]
    return DEFAULT_TOOL_TIMEOUTS_S["__default__"]


def _is_async_callable(fn: Callable[..., Any]) -> bool:
    """Detect async dispatch for ``fn``.

    ``asyncio.iscoroutinefunction`` catches a plain ``async def``;
    ``inspect.iscoroutinefunction`` catches the same shape after
    ``functools.partial`` unwrap. For callables that hide their
    async-ness behind ``__call__``, fall back to inspecting the
    bound method.
    """
    if asyncio.iscoroutinefunction(fn):
        return True
    if inspect.iscoroutinefunction(fn):
        return True
    call = getattr(fn, "__call__", None)
    if call is not None and asyncio.iscoroutinefunction(call):
        return True
    return False


async def run_tool(
    tool_name: str,
    fn: Callable[..., Any],
    kwargs: dict[str, Any],
    *,
    dedup: bool = True,
) -> Any:
    """Run an MCP tool function (sync OR async) from the async HTTP layer.

    Pipeline:
      1. Build dedup key from ``(tool_name, canonical(kwargs))``.
      2. Acquire the tool's semaphore (waits in event loop, not in
         the thread pool).
      3. If ``fn`` is ``async def``, await it directly. Otherwise
         schedule ``fn(**kwargs)`` on ``anyio.to_thread.run_sync``.
      4. Race the work against the tool's wall-clock timeout.
      5. Return the result (or a tool-shaped error dict on failure).

    Concurrent callers with matching dedup keys collapse onto a single
    in-flight execution. The semaphore is acquired once per unique
    work item, not per caller.

    All recoverable exceptions are caught and surfaced as
    ``{"status": "error", "error": ...}`` so the FastAPI handler can
    return a normal 200 + JSON envelope. ``KeyboardInterrupt`` /
    ``SystemExit`` / ``asyncio.CancelledError`` propagate so the
    server still shuts down cleanly.
    """
    deduper, semaphores = _ensure_runtime()
    key = deduper.key_for(tool_name, kwargs)
    timeout_s = _timeout_for(tool_name)
    is_async = _is_async_callable(fn)

    async def _do_work() -> Any:
        sem = semaphores.for_tool(tool_name)
        async with sem:
            t0 = time.time()
            try:
                if is_async:
                    result = await asyncio.wait_for(
                        fn(**kwargs), timeout=timeout_s,
                    )
                else:
                    # asyncio.to_thread is the modern wrapper around
                    # loop.run_in_executor; anyio.to_thread.run_sync
                    # uses the same limiter we resize at startup, which
                    # keeps the per-tool cap honest at the pool level.
                    result = await asyncio.wait_for(
                        anyio.to_thread.run_sync(
                            lambda: fn(**kwargs),
                            abandon_on_cancel=True,
                        ),
                        timeout=timeout_s,
                    )
                elapsed = time.time() - t0
                if elapsed > timeout_s * 0.8:
                    _log.warning(
                        "tool %s near timeout: %.1fs / %.1fs cap (args=%s)",
                        tool_name, elapsed, timeout_s,
                        _canonical_kwargs(kwargs)[:200],
                    )
                return result
            except TimeoutError:
                elapsed = time.time() - t0
                _log.warning(
                    "tool %s TIMED OUT after %.1fs (cap=%.1fs, args=%s)",
                    tool_name, elapsed, timeout_s,
                    _canonical_kwargs(kwargs)[:200],
                )
                return {
                    "status": "error",
                    "error": (
                        f"tool {tool_name!r} exceeded its {timeout_s:.0f}s "
                        f"wall-clock timeout. The underlying work may still "
                        f"complete in the background; retry the same call "
                        f"to either dedup onto the now-running invocation "
                        f"or get a fresh attempt."
                    ),
                    "timeout_s": timeout_s,
                    "elapsed_s": round(elapsed, 1),
                }
            except (ValueError, RuntimeError, KeyError, TypeError,
                    OSError, LookupError) as exc:
                _log.exception(
                    "tool %s raised %s", tool_name, type(exc).__name__,
                )
                return {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }

    if not dedup:
        return await _do_work()
    return await deduper.get_or_create(key, _do_work)


def runtime_stats() -> dict[str, Any]:
    """Aggregate runtime telemetry for the ``/runtime`` debug endpoint."""
    deduper, semaphores = _ensure_runtime()
    return {
        "dedup": deduper.stats(),
        "semaphores": semaphores.stats(),
        "thread_pool_limit": anyio.to_thread.current_default_thread_limiter().total_tokens,
    }
