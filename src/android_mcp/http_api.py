"""HTTP transport for android-mcp.

Mirrors audit-mcp's HTTP API shape so AILA's existing bridge layer
(`AuditMcpBridgeTool`) can be cloned with one URL change and a
schema-discovery refresh.

Routes:

  POST /tools/<name>              call tool by name; JSON body = kwargs
  GET  /tools                     list registered tools + their schemas
  GET  /tools/<name>/schema       single tool's JSON schema
  GET  /healthz                   liveness probe
  GET  /runtime                   diagnostics: per-tool semaphore/dedup stats
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from .async_runtime import configure_thread_pool, run_tool, runtime_stats
from .server import mcp

_log = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Resize the anyio worker-thread pool inside the running loop —
    # anyio's default limiter is a per-loop singleton, so it can only
    # be touched once the loop is up. Single-worker uvicorn calls
    # build_app() BEFORE booting the loop; lifespan startup runs
    # AFTER the loop starts.
    applied_limit = configure_thread_pool()
    _log.info("async runtime: thread pool limit set to %d", applied_limit)
    yield


def build_app() -> FastAPI:
    app = FastAPI(title="android-mcp", version="0.1.0", lifespan=_lifespan)

    # Build a one-shot tool catalogue. FastMCP exposes the registered
    # tools via the underlying mcp.tools dict; per-version safety means
    # we tolerate either attribute name.
    tool_index = _build_tool_index(mcp)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/tools")
    async def list_tools() -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": name,
                    "description": (tool.description or "")[:400],
                    "schema_url": f"/tools/{name}/schema",
                }
                for name, tool in tool_index.items()
            ],
        }

    @app.get("/tools/{name}/schema")
    async def tool_schema(name: str) -> dict[str, Any]:
        tool = tool_index.get(name)
        if tool is None:
            raise HTTPException(404, detail=f"unknown tool: {name}")
        return _tool_schema(tool)

    @app.post("/tools/{name}")
    async def invoke_tool(name: str, request: Request) -> Any:
        tool = tool_index.get(name)
        if tool is None:
            raise HTTPException(404, detail=f"unknown tool: {name}")
        try:
            payload = await request.json()
        except (ValueError, TypeError):
            payload = {}
        if not isinstance(payload, dict):
            raise HTTPException(400, detail="body must be a JSON object of kwargs")
        # Resolve the underlying callable once; run_tool handles
        # sync/async detection + per-tool cap + dedup + timeout.
        fn = getattr(tool, "fn", None) or getattr(tool, "func", None) or tool
        return await run_tool(name, fn, payload)

    @app.get("/runtime")
    async def runtime_diag() -> dict[str, Any]:
        stats = runtime_stats()
        stats["tool_count"] = len(tool_index)
        stats["tools"] = sorted(tool_index.keys())
        return stats

    return app


_TOOL_INDEX_CACHE: dict[str, Any] | None = None


def _build_tool_index(mcp_instance) -> dict[str, Any]:
    """Enumerate registered FastMCP tools as a ``{name: tool}`` dict.

    FastMCP ≥ 3.x exposes the tool registry only via the async
    :meth:`list_tools` method (the legacy ``tools`` / ``_tools`` /
    ``tool_registry`` attribute paths older docs referenced no longer
    exist on the public surface). We resolve the coroutine to a list
    once and cache the result at module scope; the tool set is fixed
    at import time when each ``register(mcp)`` runs, so subsequent
    enumeration is a dict lookup.

    Loop-aware: in single-worker uvicorn mode ``build_app`` runs
    BEFORE the event loop starts, so ``asyncio.run`` works directly.
    In multi-worker (``factory=True``) mode each worker calls
    ``build_app`` from INSIDE its own loop — ``asyncio.run`` raises
    ``RuntimeError: cannot be called from a running event loop``.
    Fall through to a fresh thread that hosts its own loop.
    """
    global _TOOL_INDEX_CACHE
    if _TOOL_INDEX_CACHE is not None:
        return _TOOL_INDEX_CACHE

    import asyncio
    import concurrent.futures

    try:
        asyncio.get_running_loop()
        in_loop = True
    except RuntimeError:
        in_loop = False

    if in_loop:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            tools = pool.submit(
                lambda: asyncio.run(mcp_instance.list_tools()),
            ).result()
    else:
        tools = asyncio.run(mcp_instance.list_tools())

    if not tools:
        raise RuntimeError(
            "FastMCP.list_tools() returned no tools — server.py registered "
            "nothing. Inspect android_mcp.server._register_all().",
        )
    _TOOL_INDEX_CACHE = {t.name: t for t in tools}
    return _TOOL_INDEX_CACHE


def reset_tool_index_cache() -> None:
    """Drop the cached tool index. Used by tests that re-build the app."""
    global _TOOL_INDEX_CACHE
    _TOOL_INDEX_CACHE = None


def _tool_schema(tool: Any) -> dict[str, Any]:
    # FastMCP attaches the tool's INPUT JSON schema as ``tool.parameters``
    # (already a draft-2020-12 dict). Older docs suggested ``tool.schema()``,
    # but on FastMCP 3.x that's Pydantic's deprecated class-level method —
    # it returns the FunctionTool's own schema, not the tool's inputs.
    for attr in ("parameters", "input_schema", "json_schema"):
        v = getattr(tool, attr, None)
        if isinstance(v, dict):
            return v
        if v:
            return {"raw": str(v)}
    return {"description": "no schema available"}

