"""Boot-time smoke test — every public module imports without error.

The compile test runs before any tool-specific tests so a broken
import (typo, circular dependency, missing dep) gets caught at the
fastest possible feedback step.
"""

from __future__ import annotations


def test_package_imports() -> None:
    import android_mcp  # noqa: F401

    assert android_mcp.__version__


def test_server_module() -> None:
    from android_mcp import server

    assert hasattr(server, "mcp"), "FastMCP instance missing from android_mcp.server"


def test_all_tool_modules_register() -> None:
    """Every module under tools/ must expose register(mcp)."""
    from android_mcp.tools import androguard, apktool, jadx, mobsf_static

    for module in (apktool, jadx, mobsf_static, androguard):
        assert callable(getattr(module, "register", None)), (
            f"{module.__name__} missing register(mcp)"
        )


def test_http_app_builds() -> None:
    """FastAPI app builds without crashing — catches signature drift in FastMCP."""
    from android_mcp.http_api import build_app

    app = build_app()
    routes = [r.path for r in app.routes]
    assert "/healthz" in routes
    assert "/tools" in routes
