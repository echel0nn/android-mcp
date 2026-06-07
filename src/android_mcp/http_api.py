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
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from .server import mcp

_log = logging.getLogger(__name__)


def build_app() -> FastAPI:
    app = FastAPI(title="android-mcp", version="0.1.0")

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
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            raise HTTPException(400, detail="body must be a JSON object of kwargs")
        try:
            result = await _invoke(tool, **payload)
        except TypeError as exc:
            raise HTTPException(400, detail=f"kwargs error: {exc}") from exc
        except Exception as exc:
            _log.exception("tool %s raised", name)
            raise HTTPException(500, detail=f"{type(exc).__name__}: {exc}") from exc
        return result

    @app.get("/runtime")
    async def runtime_diag() -> dict[str, Any]:
        # Mirror audit-mcp's /runtime shape so a single ops dashboard
        # can show per-tool concurrency state.
        return {
            "tool_count": len(tool_index),
            "tools": sorted(tool_index.keys()),
        }

    return app


def _build_tool_index(mcp_instance) -> dict[str, Any]:
    """Best-effort enumeration of registered tools across FastMCP versions."""
    for attr in ("tools", "_tools", "tool_registry"):
        candidate = getattr(mcp_instance, attr, None)
        if isinstance(candidate, dict):
            return dict(candidate)
        if hasattr(candidate, "items") and callable(candidate.items):
            return dict(candidate.items())
    raise RuntimeError(
        "could not enumerate FastMCP tools — server.py registered "
        "nothing, or the FastMCP API shifted; inspect mcp.* attributes",
    )


def _tool_schema(tool: Any) -> dict[str, Any]:
    if hasattr(tool, "schema") and callable(tool.schema):
        return tool.schema()
    for attr in ("parameters", "input_schema", "json_schema"):
        v = getattr(tool, attr, None)
        if v:
            return v if isinstance(v, dict) else {"raw": str(v)}
    return {"description": "no schema available"}


async def _invoke(tool: Any, **kwargs: Any) -> Any:
    """Call a FastMCP tool, awaiting if it's async."""
    fn = getattr(tool, "fn", None) or getattr(tool, "func", None) or tool
    out = fn(**kwargs)
    if hasattr(out, "__await__"):
        out = await out
    return out
