"""android-mcp FastMCP server — registers all tool handlers.

Each tool lives in `tools/<name>.py` and exposes a single top-level
`register(mcp)` function that attaches `@mcp.tool()`-decorated handlers
to the shared FastMCP instance.

This shape keeps every tool isolated: one file = one CLI/library
wrapper, one schema, one set of tests under `tests/test_<name>.py`.
Adding a new mobile-security tool is mechanically the same operation
each time:

    1. drop a new file under tools/
    2. expose register(mcp)
    3. import + call from this module's `_register_all`
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP

_log = logging.getLogger(__name__)

mcp = FastMCP("android-mcp")


def _register_all() -> None:
    """Import every tool module and attach its handlers to the MCP.

    Order: every per-tool wrapper under ``tools/`` first, then the
    composite module under ``android_mcp/composite.py``. Composite
    handlers depend on the per-tool wrappers being on the import
    path but NOT on them being registered first — each composite
    handler imports its own dependencies lazily inside the call.
    Registering in this order keeps the failure mode predictable:
    if a per-tool wrapper fails to register, the composite handlers
    still surface and the operator sees both halves of the gap.
    """
    from . import composite
    from .tools import (
        adb,
        androguard,
        apksigner,
        apktool,
        drozer,
        frida_helpers,
        jadx,
        lief_so,
        mobsf_static,
        objection,
        react_native,
        yara_decompiled,
    )

    modules = (
        adb,
        androguard,
        apksigner,
        apktool,
        drozer,
        frida_helpers,
        jadx,
        lief_so,
        mobsf_static,
        objection,
        react_native,
        yara_decompiled,
        composite,
    )
    for module in modules:
        if not hasattr(module, "register"):
            _log.warning("tool module %s has no register() function — skipping", module.__name__)
            continue
        try:
            module.register(mcp)
        except Exception:
            _log.exception("failed to register tool module %s", module.__name__)


_register_all()
