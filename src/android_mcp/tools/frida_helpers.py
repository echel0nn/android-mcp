"""Frida helpers — list devices, dump process modules, attach + trace calls.

frida-python is an optional dependency declared under
`[project.optional-dependencies].dynamic` in pyproject.toml. Most
operators run `frida-server` on the device and drive it externally;
this module is for the cases where you want a frida session to surface
through the same MCP surface as androguard / apktool / mobsf so a VR
investigation can ask for a quick module dump or method-call trace
without leaving the audit pipeline.

Every handler imports `frida` lazily and raises a clean RuntimeError
with the install hint when the dependency is missing, so the rest of
the MCP keeps booting on a frida-less host.

Method-signature syntax accepted by `frida_attach_and_trace_calls`:

    native:<library_name>:<symbol>     e.g. native:libc.so:open
    java:<full.class.name>:<method>    e.g. java:java.lang.String:valueOf

Native signatures resolve via `Module.findExportByName`. Java
signatures resolve via `Java.use(...)` and replace the method
implementation with a trampoline that records the call and forwards
to the original. Both push entries into an in-script `traces` array
that the host fetches via RPC export when the trace window expires.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

_log = logging.getLogger(__name__)

# Largest tracing window the host accepts. Anything past 5 minutes is
# better served by a long-running frida-trace session driven externally;
# parking the MCP socket for hours defeats the per-tool semaphore.
_MAX_TRACE_DURATION_S = 300

# Default tracing window. 5 seconds catches startup behavior and most
# UI interactions without holding the worker too long.
_DEFAULT_TRACE_DURATION_S = 5

# Exact install hint required by PRD §A-1 acceptance. Don't reflow.
_INSTALL_HINT = "frida not installed - pip install 'android-mcp[dynamic]'"


def _import_frida() -> Any:
    """Lazy-import frida or raise the canonical RuntimeError.

    Keeping the import inside this helper (called per-handler) lets the
    rest of the MCP boot on hosts that intentionally skip the `dynamic`
    optional-dependencies group. The RuntimeError carries the exact
    install command so the operator does not need to look it up.
    """
    try:
        import frida  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(_INSTALL_HINT) from exc
    return frida


def register(mcp: Any) -> None:
    @mcp.tool()
    async def frida_list_running_devices() -> list[dict[str, Any]]:
        """Enumerate devices the local frida runtime can see.

        Returns:
            list of `{id, name, type}` dicts. `type` is one of
            `"local"`, `"usb"`, `"remote"`. Empty list when no
            devices are reachable.

        Raises:
            RuntimeError: frida package not installed.
        """
        frida = _import_frida()
        loop = asyncio.get_event_loop()
        devices = await loop.run_in_executor(
            None,
            lambda: frida.get_device_manager().enumerate_devices(),
        )
        return [
            {
                "id": getattr(d, "id", ""),
                "name": getattr(d, "name", ""),
                "type": getattr(d, "type", "unknown"),
            }
            for d in devices
        ]

    @mcp.tool()
    async def frida_dump_process_modules(
        device_id: str,
        pid: int,
    ) -> dict[str, Any]:
        """Attach to a process and enumerate its loaded modules.

        Args:
            device_id: Device id from `frida_list_running_devices`,
                e.g. `"local"`, `"emulator-5554"`, `"usb-<serial>"`.
            pid: Process id on the target device. Resolve a package
                name to its pid externally (frida-ps or
                `Device.enumerate_processes()`).

        Returns:
            dict with `device_id`, `pid`, and `modules` — a list of
            `{name, base, size, path}` where `base` is hex-formatted.

        Raises:
            RuntimeError: frida not installed.
            frida.ServerNotRunningError / frida.ProcessNotFoundError /
                frida.TransportError: surfaced unmodified — the caller
                needs the exact error class to decide retry policy.
        """
        frida = _import_frida()
        loop = asyncio.get_event_loop()

        def _dump() -> list[dict[str, Any]]:
            device = frida.get_device(device_id)
            session = device.attach(pid)
            try:
                modules = session.enumerate_modules()
                return [
                    {
                        "name": getattr(m, "name", ""),
                        "base": hex(getattr(m, "base_address", 0)),
                        "size": int(getattr(m, "size", 0)),
                        "path": getattr(m, "path", ""),
                    }
                    for m in modules
                ]
            finally:
                try:
                    session.detach()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    _log.debug("detach failed", exc_info=True)

        modules = await loop.run_in_executor(None, _dump)
        return {"device_id": device_id, "pid": pid, "modules": modules}

    @mcp.tool()
    async def frida_attach_and_trace_calls(
        device_id: str,
        pid: int,
        method_signatures: list[str],
        duration_s: int = _DEFAULT_TRACE_DURATION_S,
    ) -> dict[str, Any]:
        """Trace method calls in a running process for a fixed window.

        Builds a frida JS script that installs an interceptor for every
        signature in `method_signatures`, attaches to the target, holds
        the trace open for `duration_s` seconds, fetches the captured
        events via RPC export, and detaches.

        Signature syntax:
            `native:<library>:<symbol>` — e.g. `native:libc.so:open`
            `java:<class.name>:<method>` — e.g. `java:java.lang.String:valueOf`

        Args:
            device_id: Device id from `frida_list_running_devices`.
            pid: Process id on the device.
            method_signatures: List of signature strings (see above).
                Signatures whose prefix is not `native:` or `java:` go
                into `skipped_signatures` in the response.
            duration_s: Tracing window in seconds. Must be in
                `(0, 300]`; values outside that range raise ValueError.

        Returns:
            dict with `device_id`, `pid`, `duration_s`,
            `installed_signatures` (signatures that parsed cleanly),
            `skipped_signatures` (signatures with unknown syntax), and
            `events` — chronological list of `{signature, timestamp_ms,
            thread?, args?}` captured during the window.

        Raises:
            RuntimeError: frida not installed.
            ValueError: `duration_s` non-positive or > 300.
        """
        if duration_s <= 0 or duration_s > _MAX_TRACE_DURATION_S:
            raise ValueError(
                f"duration_s must be in (0, {_MAX_TRACE_DURATION_S}], got {duration_s}",
            )

        frida = _import_frida()
        installed, skipped, script_source = _build_trace_script(method_signatures)

        loop = asyncio.get_event_loop()

        def _trace() -> list[dict[str, Any]]:
            device = frida.get_device(device_id)
            session = device.attach(pid)
            try:
                script = session.create_script(script_source)
                script.load()
                # Hold the trace open for the configured window. The
                # injected interceptors push events into a JS-side
                # array; the RPC export call below drains it.
                time.sleep(duration_s)
                exports = getattr(script, "exports_sync", None) or script.exports
                events = exports.get_traces()
                return list(events) if events else []
            finally:
                try:
                    session.detach()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    _log.debug("detach failed", exc_info=True)

        events = await loop.run_in_executor(None, _trace)
        return {
            "device_id": device_id,
            "pid": pid,
            "duration_s": duration_s,
            "installed_signatures": installed,
            "skipped_signatures": skipped,
            "events": events,
        }


def _build_trace_script(
    signatures: list[str],
) -> tuple[list[str], list[str], str]:
    """Build the JS trace script and partition signatures.

    Returns `(installed, skipped, source)`:
        `installed` — signatures matching a known prefix; each gets a
            runtime install clause in the script source.
        `skipped` — signatures with unknown syntax; the host skips
            them without burning a frida resolution attempt.
        `source` — full JS payload ready for `session.create_script`.

    The frida runtime may still fail to resolve an `installed`
    signature at script load (e.g. the named module isn't present in
    the process), but that surfaces as an empty trace, not a
    build-time skip — frida JS errors there are caught and logged
    inside each clause.
    """
    installed: list[str] = []
    skipped: list[str] = []
    clauses: list[str] = []
    for sig in signatures:
        parts = sig.split(":")
        if len(parts) == 3 and parts[0] == "native":
            module_name, symbol = parts[1], parts[2]
            clauses.append(_native_clause(sig, module_name, symbol))
            installed.append(sig)
        elif len(parts) == 3 and parts[0] == "java":
            class_name, method_name = parts[1], parts[2]
            clauses.append(_java_clause(sig, class_name, method_name))
            installed.append(sig)
        else:
            skipped.append(sig)

    source = _SCRIPT_PRELUDE + "\n".join(clauses) + _SCRIPT_EPILOGUE
    return installed, skipped, source


def _native_clause(signature: str, module_name: str, symbol: str) -> str:
    """JS that installs an `Interceptor.attach` for one native symbol."""
    sig_j = json.dumps(signature)
    mod_j = json.dumps(module_name)
    sym_j = json.dumps(symbol)
    return (
        "(function() {\n"
        f"    var ptr = Module.findExportByName({mod_j}, {sym_j});\n"
        "    if (ptr === null) { return; }\n"
        "    Interceptor.attach(ptr, {\n"
        "        onEnter: function(args) {\n"
        "            traces.push({\n"
        f"                signature: {sig_j},\n"
        "                timestamp_ms: Date.now(),\n"
        "                thread: this.threadId\n"
        "            });\n"
        "        }\n"
        "    });\n"
        "})();\n"
    )


def _java_clause(signature: str, class_name: str, method_name: str) -> str:
    """JS that swaps a Java method's implementation with a trace trampoline."""
    sig_j = json.dumps(signature)
    cls_j = json.dumps(class_name)
    method_j = json.dumps(method_name)
    return (
        "Java.perform(function() {\n"
        "    try {\n"
        f"        var klass = Java.use({cls_j});\n"
        f"        var method = klass[{method_j}];\n"
        "        if (method === undefined) { return; }\n"
        "        method.implementation = function() {\n"
        "            traces.push({\n"
        f"                signature: {sig_j},\n"
        "                timestamp_ms: Date.now(),\n"
        "                args: Array.prototype.slice.call(arguments).map(String)\n"
        "            });\n"
        "            return method.apply(this, arguments);\n"
        "        };\n"
        "    } catch (e) {\n"
        "        /* class not yet available or method missing -- empty trace */\n"
        "    }\n"
        "});\n"
    )


_SCRIPT_PRELUDE = "var traces = [];\n"

_SCRIPT_EPILOGUE = (
    "\nrpc.exports = {\n"
    "    getTraces: function() {\n"
    "        var snapshot = traces.slice();\n"
    "        traces.length = 0;\n"
    "        return snapshot;\n"
    "    }\n"
    "};\n"
)
