"""Mobile-security tool wrappers.

Each module here exposes a `register(mcp)` function that attaches
`@mcp.tool()`-decorated handlers to the shared FastMCP instance.

One file per tool. Add a new tool by:

  1. dropping a new module here, e.g. `tools/qark.py`
  2. exposing `register(mcp)`
  3. importing + calling it from `server.py::_register_all`
  4. adding a test under `tests/test_<tool>.py`

This module is intentionally a thin package marker so the import in
`server.py` (`from .tools import apktool, jadx, ...`) works without
boot-time side-effects.
"""
