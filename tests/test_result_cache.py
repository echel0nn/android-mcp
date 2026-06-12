"""Tests for android_mcp.result_cache LRU + inflight-future dedup."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from android_mcp import result_cache


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-test cache + stats reset."""
    result_cache._CACHE.clear()  # type: ignore[attr-defined]
    for k in result_cache._STATS:  # type: ignore[attr-defined]
        result_cache._STATS[k] = 0  # type: ignore[attr-defined]
    result_cache._BY_ACTION.clear()  # type: ignore[attr-defined]
    yield
    result_cache._CACHE.clear()  # type: ignore[attr-defined]


def _sha256_path(prefix: str = "9228be90") -> str:
    """Synthesize an APK path with a hex-SHA-256-shaped basename."""
    h = prefix + "f" * (64 - len(prefix))
    return rf"C:\Users\OP\.android-mcp\uploads\shared\{h}.apk"


async def _make_invoker(value: Any, delay_s: float = 0.0):
    async def _invoker():
        if delay_s:
            await asyncio.sleep(delay_s)
        return value
    return _invoker


@pytest.mark.asyncio
async def test_non_cacheable_action_bypasses_cache() -> None:
    """`adb_devices` is not in CACHEABLE_ACTIONS → always invokes."""
    calls = 0

    async def invoker():
        nonlocal calls
        calls += 1
        return {"devices": []}

    await result_cache.cache_dispatch("adb_devices", {}, invoker)
    await result_cache.cache_dispatch("adb_devices", {}, invoker)
    assert calls == 2
    s = result_cache.stats()
    assert s["non_cacheable_dispatched"] == 2
    assert s["hits"] == 0
    assert s["misses"] == 0


@pytest.mark.asyncio
async def test_no_apk_sha256_bypasses_cache() -> None:
    """Cacheable action but apk_path lacks a SHA-256 → bypass."""
    calls = 0

    async def invoker():
        nonlocal calls
        calls += 1
        return {"result": calls}

    kwargs = {"apk_path": "C:/operator/dev/build/output/app-debug.apk"}
    await result_cache.cache_dispatch("classify_behavior", kwargs, invoker)
    await result_cache.cache_dispatch("classify_behavior", kwargs, invoker)
    assert calls == 2  # both bypassed
    s = result_cache.stats()
    assert s["non_cacheable_dispatched"] == 2


@pytest.mark.asyncio
async def test_cacheable_action_with_sha256_caches_second_call() -> None:
    """First call = miss + invoker run. Second call = hit + no invoker."""
    calls = 0

    async def invoker():
        nonlocal calls
        calls += 1
        return {"behaviors": ["A", "B"], "n": calls}

    kwargs = {"apk_path": _sha256_path()}

    r1 = await result_cache.cache_dispatch("classify_behavior", kwargs, invoker)
    r2 = await result_cache.cache_dispatch("classify_behavior", kwargs, invoker)
    assert calls == 1
    assert r1 == r2
    s = result_cache.stats()
    assert s["hits"] == 1
    assert s["misses"] == 1


@pytest.mark.asyncio
async def test_concurrent_callers_share_inflight_future() -> None:
    """N concurrent calls to the same key → 1 invoker run + N-1 inflight_waits."""
    calls = 0

    async def invoker():
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return {"result": "shared"}

    kwargs = {"apk_path": _sha256_path()}

    results = await asyncio.gather(
        result_cache.cache_dispatch("classify_behavior", kwargs, invoker),
        result_cache.cache_dispatch("classify_behavior", kwargs, invoker),
        result_cache.cache_dispatch("classify_behavior", kwargs, invoker),
        result_cache.cache_dispatch("classify_behavior", kwargs, invoker),
        result_cache.cache_dispatch("classify_behavior", kwargs, invoker),
        result_cache.cache_dispatch("classify_behavior", kwargs, invoker),
    )
    assert calls == 1  # only ONE invoker run
    assert all(r == {"result": "shared"} for r in results)
    s = result_cache.stats()
    assert s["misses"] == 1
    assert s["inflight_waits"] == 5  # 6 calls, 1 took the miss path


@pytest.mark.asyncio
async def test_different_apks_get_different_cache_entries() -> None:
    """Same action, different APK SHA256 → independent cache entries."""
    calls = 0

    async def invoker():
        nonlocal calls
        calls += 1
        return {"call": calls}

    apk_a = {"apk_path": _sha256_path("aaaaaaaa")}
    apk_b = {"apk_path": _sha256_path("bbbbbbbb")}
    await result_cache.cache_dispatch("classify_behavior", apk_a, invoker)
    await result_cache.cache_dispatch("classify_behavior", apk_b, invoker)
    await result_cache.cache_dispatch("classify_behavior", apk_a, invoker)
    await result_cache.cache_dispatch("classify_behavior", apk_b, invoker)
    assert calls == 2  # one per distinct APK
    s = result_cache.stats()
    assert s["misses"] == 2
    assert s["hits"] == 2


@pytest.mark.asyncio
async def test_different_args_get_different_cache_entries() -> None:
    """Same APK + action but different options → independent entries."""
    calls = 0

    async def invoker():
        nonlocal calls
        calls += 1
        return {"call": calls}

    apk = _sha256_path()
    kw_quick = {"apk_path": apk, "profile": "quick"}
    kw_full = {"apk_path": apk, "profile": "full"}
    await result_cache.cache_dispatch("mobsf_static_scan", kw_quick, invoker)
    await result_cache.cache_dispatch("mobsf_static_scan", kw_full, invoker)
    await result_cache.cache_dispatch("mobsf_static_scan", kw_quick, invoker)
    assert calls == 2


@pytest.mark.asyncio
async def test_exception_is_not_cached() -> None:
    """Invoker raises → exception propagates AND cache entry is cleared."""
    calls = 0

    async def boom():
        nonlocal calls
        calls += 1
        raise RuntimeError(f"boom #{calls}")

    kwargs = {"apk_path": _sha256_path()}
    with pytest.raises(RuntimeError, match="boom #1"):
        await result_cache.cache_dispatch("classify_behavior", kwargs, boom)
    # Next call retries (no cached exception).
    with pytest.raises(RuntimeError, match="boom #2"):
        await result_cache.cache_dispatch("classify_behavior", kwargs, boom)
    assert calls == 2


@pytest.mark.asyncio
async def test_invalidate_all_clears_entries() -> None:
    async def invoker():
        return {"ok": True}

    kwargs = {"apk_path": _sha256_path()}
    await result_cache.cache_dispatch("classify_behavior", kwargs, invoker)
    assert result_cache.stats()["entries"] == 1
    evicted = result_cache.invalidate_all()
    assert evicted == 1
    assert result_cache.stats()["entries"] == 0


@pytest.mark.asyncio
async def test_stats_tracks_per_action_counts() -> None:
    async def invoker():
        return {"ok": True}

    apk = _sha256_path()
    await result_cache.cache_dispatch("classify_behavior", {"apk_path": apk}, invoker)
    await result_cache.cache_dispatch("classify_behavior", {"apk_path": apk}, invoker)
    await result_cache.cache_dispatch("capa_scan", {"apk_path": apk}, invoker)
    s = result_cache.stats()
    assert s["by_action"]["classify_behavior"]["hits"] == 1
    assert s["by_action"]["classify_behavior"]["misses"] == 1
    assert s["by_action"]["capa_scan"]["misses"] == 1
