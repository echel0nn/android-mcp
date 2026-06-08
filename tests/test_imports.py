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
    """Every per-tool wrapper plus the composite module exposes register(mcp)."""
    from android_mcp import composite
    from android_mcp.tools import (
        adb,
        androbugs,
        androguard,
        apksigner,
        apktool,
        drozer,
        frida_helpers,
        jadx,
        lief_so,
        mobsf_static,
        objection,
        qark,
        yara_decompiled,
    )

    modules = (
        adb,
        androbugs,
        androguard,
        apksigner,
        apktool,
        drozer,
        frida_helpers,
        jadx,
        lief_so,
        mobsf_static,
        objection,
        qark,
        yara_decompiled,
        composite,
    )
    for module in modules:
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


# Tool-handler floor. Every name here must appear at ``GET /tools`` once
# ``server._register_all`` has run. Split by module so a registration
# regression points the operator straight at the file to inspect.
#
# Per-tool handler counts: adb (5), androbugs (1), androguard (1),
# apksigner (1), apktool (1), drozer (1), frida_helpers (3), jadx (1),
# lief_so (1), mobsf_static (1), objection (2), qark (1),
# yara_decompiled (1) — total 20 handlers across 13 wrapper modules.
# Composite ships all 4 PRD §A composite tools as of A-12. The handler
# floor below mirrors the registered set; adding a fifth composite tool
# means growing this set + adding tests under
# ``tests/test_composite_<name>.py`` and walking ``register`` to
# capture the new function.
_EXPECTED_PER_TOOL_HANDLERS: frozenset[str] = frozenset({
    "adb_devices",
    "adb_install",
    "adb_uninstall",
    "adb_logcat_capture",
    "adb_dumpsys",
    "androbugs_scan",
    "androguard_summary",
    "verify_apk_signing",
    "apktool_decode",
    "drozer_scan_apk",
    "frida_list_running_devices",
    "frida_dump_process_modules",
    "frida_attach_and_trace_calls",
    "jadx_decompile",
    "analyze_native_libs",
    "mobsf_scan",
    "objection_patch_apk",
    "objection_explore",
    "qark_scan",
    "yara_scan_dir",
})

_EXPECTED_COMPOSITE_HANDLERS: frozenset[str] = frozenset({
    "classify_behavior",
    "find_secrets",
    "verify_capabilities",
    "compute_risk_score",
})


def test_http_app_lists_full_tool_surface() -> None:
    """``GET /tools`` surfaces every per-tool handler plus the live composite set.

    The PRD §B-14 acceptance is "13+ tools at /tools"; this asserts the
    concrete handler names so a missing import in ``_register_all`` fails
    with a useful diff instead of a single off-by-one count error.
    """
    from fastapi.testclient import TestClient

    from android_mcp.http_api import build_app

    with TestClient(build_app()) as client:
        response = client.get("/tools")
        assert response.status_code == 200, response.text
        names = {entry["name"] for entry in response.json()["tools"]}

    missing_per_tool = _EXPECTED_PER_TOOL_HANDLERS - names
    assert not missing_per_tool, (
        f"GET /tools missing per-tool handlers: {sorted(missing_per_tool)}"
    )

    missing_composite = _EXPECTED_COMPOSITE_HANDLERS - names
    assert not missing_composite, (
        f"GET /tools missing composite handlers: {sorted(missing_composite)}"
    )

    # PRD §B-14 floor: at least 13 per-tool entries surface at /tools.
    # We register 20 per-tool handlers from 13 wrapper modules so this
    # gives plenty of headroom; the assertion guards against silent
    # regression where a wrapper module is dropped from the loop.
    per_tool_present = _EXPECTED_PER_TOOL_HANDLERS & names
    assert len(per_tool_present) >= 13, (
        f"GET /tools per-tool handler count regressed: {len(per_tool_present)} < 13"
    )
