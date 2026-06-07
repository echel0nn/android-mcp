"""android-mcp — Mobile security audit MCP server.

Wraps the standard mobile-security toolchain (apktool, jadx, mobsf,
androguard, frida, drozer, ...) behind one MCP surface so an AI agent
can drive APK audits without managing tool installations or invocation
syntax per tool.

The HTTP API mirrors audit-mcp's shape (POST /tools/<name>, GET /tools,
GET /tools/<name>/schema) so AILA's existing bridge layer can call this
server without code changes — register it under `mcp_servers.android`
with the same kwargs validation pipeline.

Public surface:

    from android_mcp import mcp                # FastMCP instance
    from android_mcp.async_runtime import …    # shared concurrency primitives
"""

from .server import mcp

__all__ = ["mcp"]
__version__ = "0.1.0"
