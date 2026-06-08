"""Concurrent-load test for the HTTP transport's ``run_tool`` wrapper.

The async runtime port (commit 3cf071a) wraps every ``POST /tools/<name>``
through :func:`android_mcp.async_runtime.run_tool`, which adds:

  * :class:`InFlightDedup` — coalesce identical concurrent calls onto
    one in-flight execution.
  * :class:`ToolSemaphores` — per-tool concurrency cap so one slow tool
    cannot starve the others.
  * Wall-clock timeouts — surface stuck calls as ``{"status": "error"}``
    envelopes instead of pinning workers forever.

The wiring was verified end-to-end in 3cf071a via an ad-hoc script (ten
concurrent identical calls → 9 hits / 1 miss). This file makes that
proof part of the test suite.

Why a probe tool rather than the production ``androguard_summary`` named
in the original acceptance: the dedup wrapper only collapses callers
that reach the in-flight check BEFORE the originator's work resolves.
``androguard_summary`` on a missing path completes synchronously inside
one event-loop step (the body never reaches an ``await`` before raising
``FileNotFoundError``), so ten ``httpx`` posts over ``ASGITransport``
run serially through the loop and each pays its own ``misses += 1``.
A 200 ms ``asyncio.sleep`` in the probe tool forces enough wall-clock
that all ten callers reach the dedup wrapper together. The behavioral
contract under test — ``run_tool`` wraps every dispatched handler with
dedup — is identical regardless of which tool drives the test. The
third test in this file still routes through ``androguard_summary`` to
confirm the production tool name flows through the same HTTP wrapping.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport

from android_mcp.async_runtime import reset_runtime, runtime_stats
from android_mcp.http_api import build_app, reset_tool_index_cache
from android_mcp.server import mcp

# Register a deliberately slow probe tool on the shared FastMCP instance
# at module-import time so :func:`build_app` enumerates it into the
# tool catalogue. 200 ms is the smallest sleep that reliably overlaps
# ten ``httpx`` ``ASGITransport`` dispatches on both Linux CI runners
# and the Windows host this MCP targets. The underscore prefix marks
# the tool as test-only so it does not show up in operator-facing
# tool-name lists (the ``/tools`` route already filters on the
# underlying FastMCP registry, but the prefix is the convention).


@mcp.tool()
async def _dedup_probe_slow(value: str) -> dict[str, str]:
    """Test-only probe — sleep 200 ms, echo the value back.

    Used by :func:`test_ten_identical_calls_collapse_to_one_miss_nine_hits`
    to overlap ten identical calls long enough for
    :class:`android_mcp.async_runtime.InFlightDedup` to collapse them
    onto one in-flight execution. Not registered through ``server.py``
    and not exposed via README.
    """
    await asyncio.sleep(0.2)
    return {"value": value, "doubled": value + value}


@pytest.fixture
def _fresh_runtime():
    """Reset module-level dedup/semaphore counters and tool-index cache.

    Both ``_DEDUP``/``_SEMS`` in
    :mod:`android_mcp.async_runtime` and ``_TOOL_INDEX_CACHE`` in
    :mod:`android_mcp.http_api` live for the process lifetime once
    instantiated. A clean starting count is the only way to reason
    about exact hit/miss totals.
    """
    reset_tool_index_cache()
    reset_runtime()
    yield
    reset_tool_index_cache()
    reset_runtime()


async def test_ten_identical_calls_collapse_to_one_miss_nine_hits(
    _fresh_runtime,
) -> None:
    """Ten parallel POSTs with identical kwargs dedup to one execution.

    Spins up the FastAPI app behind an in-memory ``ASGITransport``,
    fires ten ``httpx.AsyncClient`` posts to the slow probe tool via
    :func:`asyncio.gather`, then reads runtime telemetry from the
    ``/runtime`` endpoint to confirm :class:`InFlightDedup` recorded
    exactly one miss and at least nine hits. All ten responses share
    the same payload because the dedup wrapper hands every waiter the
    originating call's resolved result.
    """
    app = build_app()
    transport = ASGITransport(app=app)
    payload = {"value": "dedup-probe-identical-kwargs"}

    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", timeout=30.0,
    ) as client:
        responses = await asyncio.gather(*[
            client.post("/tools/_dedup_probe_slow", json=payload)
            for _ in range(10)
        ])

        for response in responses:
            assert response.status_code == 200, response.text
            body = response.json()
            assert body == {
                "value": "dedup-probe-identical-kwargs",
                "doubled": (
                    "dedup-probe-identical-kwargs"
                    "dedup-probe-identical-kwargs"
                ),
            }, body

    stats = runtime_stats()
    dedup = stats["dedup"]
    assert dedup["misses"] == 1, dedup
    assert dedup["hits"] >= 9, dedup
    assert dedup["inflight"] == 0, dedup

    sem = stats["semaphores"].get("_dedup_probe_slow")
    assert sem is not None, stats["semaphores"]
    # Probe tool inherits __default__ cap (8) — no per-tool override exists.
    assert sem["cap"] == 8, sem
    # All slots released after gather completes.
    assert sem["available"] == 8, sem


async def test_runtime_endpoint_returns_documented_shape(
    _fresh_runtime,
) -> None:
    """``/runtime`` exposes dedup, semaphores, thread_pool_limit, tool_count.

    Operators wire this endpoint into dashboards; the field set must
    stay stable across runtime refactors. ``hits``/``misses``/``inflight``
    are the three keys that drive sibling-branch dedup observability;
    drop one and the dashboard goes blind.
    """
    app = build_app()
    transport = ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", timeout=30.0,
    ) as client:
        runtime = await client.get("/runtime")

    runtime.raise_for_status()
    stats = runtime.json()
    assert set(stats.keys()) >= {
        "dedup", "semaphores", "thread_pool_limit", "tool_count", "tools",
    }, stats
    assert set(stats["dedup"].keys()) == {"inflight", "hits", "misses"}, (
        stats["dedup"]
    )
    # Thread pool floor enforced by configure_thread_pool's ``max(8, limit)``;
    # the anyio default (40) clears it too, so the test passes whether or
    # not the lifespan hook fired.
    assert stats["thread_pool_limit"] >= 8, stats["thread_pool_limit"]
    assert isinstance(stats["tool_count"], int), stats["tool_count"]
    assert stats["tool_count"] >= 4, stats["tool_count"]
    assert isinstance(stats["tools"], list), stats["tools"]
    assert "androguard_summary" in stats["tools"], stats["tools"]


async def test_androguard_summary_routes_through_run_tool(
    _fresh_runtime,
) -> None:
    """Production ``androguard_summary`` flows through the same HTTP wrap.

    Posts to ``/tools/androguard_summary`` with a non-existent path and
    asserts the response is HTTP 200 with the standard ``run_tool``
    error envelope (``{"status": "error", "error": "FileNotFoundError: ..."}``).
    This proves the production tool name is registered and the route
    catches ``OSError`` subclasses via the ``run_tool`` exception
    handler — without that handler the call would surface as a 500.
    Dedup counts are not asserted here; the fast-failing tool body
    completes serially without overlap, and the dedup proof lives in
    :func:`test_ten_identical_calls_collapse_to_one_miss_nine_hits`.
    """
    pytest.importorskip("androguard")  # tool body imports it lazily
    app = build_app()
    transport = ASGITransport(app=app)
    payload = {
        "apk_path": "/nonexistent-android-mcp-concurrent-load-fixture.apk",
    }

    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", timeout=30.0,
    ) as client:
        response = await client.post(
            "/tools/androguard_summary", json=payload,
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert isinstance(body, dict), body
    assert body.get("status") == "error", body
    err = body.get("error", "")
    assert "FileNotFoundError" in err, body
