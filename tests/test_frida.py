"""Tests for the frida_helpers wrapper.

frida-python is an optional dep; the handlers must work on a host
where it is intentionally absent (clean RuntimeError) AND must drive
the real Python API correctly when it is present. Both surfaces are
covered here without requiring a running frida-server.

The strategy is to patch `_import_frida` so each test substitutes a
MagicMock frida module with the exact API surface the handler under
test exercises. `time.sleep` is also patched to keep the trace test
fast.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest


def _resolve_handler(name: str) -> Any:
    """Run `register(_MCP())` and return the named handler.

    The FastMCP `@mcp.tool()` decorator returns the original function
    untouched, so capturing it through a tiny stand-in MCP is enough.
    """
    from android_mcp.tools.frida_helpers import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get(name)
    assert callable(fn), f"register did not capture {name!r}"
    return fn


def _make_device(device_id: str, name: str, dtype: str) -> MagicMock:
    d = MagicMock()
    d.id = device_id
    d.name = name
    d.type = dtype
    return d


def _make_module(name: str, base: int, size: int, path: str) -> MagicMock:
    m = MagicMock()
    m.name = name
    m.base_address = base
    m.size = size
    m.path = path
    return m


# ---------------------------------------------------------------------------
# _import_frida — install-hint envelope
# ---------------------------------------------------------------------------


def test_import_frida_raises_clean_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """When frida is not installed, the helper raises RuntimeError with
    the exact install hint required by PRD §A-1."""
    from android_mcp.tools import frida_helpers

    # Force the lazy `import frida` inside _import_frida to fail.
    monkeypatch.setitem(sys.modules, "frida", None)

    with pytest.raises(RuntimeError) as exc_info:
        frida_helpers._import_frida()

    assert str(exc_info.value) == (
        "frida not installed - pip install 'android-mcp[dynamic]'"
    )
    assert isinstance(exc_info.value.__cause__, ImportError)


async def test_list_devices_raises_when_frida_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "frida", None)
    handler = _resolve_handler("frida_list_running_devices")
    with pytest.raises(RuntimeError, match="frida not installed"):
        await handler()


async def test_dump_modules_raises_when_frida_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "frida", None)
    handler = _resolve_handler("frida_dump_process_modules")
    with pytest.raises(RuntimeError, match="frida not installed"):
        await handler(device_id="local", pid=1234)


async def test_trace_calls_raises_when_frida_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "frida", None)
    handler = _resolve_handler("frida_attach_and_trace_calls")
    with pytest.raises(RuntimeError, match="frida not installed"):
        await handler(device_id="local", pid=1234, method_signatures=[])


# ---------------------------------------------------------------------------
# frida_list_running_devices
# ---------------------------------------------------------------------------


async def test_list_devices_returns_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_frida = MagicMock()
    fake_frida.get_device_manager.return_value.enumerate_devices.return_value = [
        _make_device("local", "Local System", "local"),
        _make_device("emulator-5554", "Android Emulator 5554", "usb"),
        _make_device("tcp@10.0.0.5:27042", "Remote Pixel", "remote"),
    ]
    monkeypatch.setattr(
        "android_mcp.tools.frida_helpers._import_frida",
        lambda: fake_frida,
    )

    handler = _resolve_handler("frida_list_running_devices")
    devices = await handler()

    assert devices == [
        {"id": "local", "name": "Local System", "type": "local"},
        {"id": "emulator-5554", "name": "Android Emulator 5554", "type": "usb"},
        {"id": "tcp@10.0.0.5:27042", "name": "Remote Pixel", "type": "remote"},
    ]


async def test_list_devices_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_frida = MagicMock()
    fake_frida.get_device_manager.return_value.enumerate_devices.return_value = []
    monkeypatch.setattr(
        "android_mcp.tools.frida_helpers._import_frida",
        lambda: fake_frida,
    )

    handler = _resolve_handler("frida_list_running_devices")
    assert await handler() == []


# ---------------------------------------------------------------------------
# frida_dump_process_modules
# ---------------------------------------------------------------------------


async def test_dump_process_modules_returns_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_session = MagicMock()
    fake_session.enumerate_modules.return_value = [
        _make_module("libc.so", 0x7F1234000000, 1_500_000, "/system/lib64/libc.so"),
        _make_module("libssl.so", 0x7F1234500000, 750_000, "/system/lib64/libssl.so"),
    ]
    fake_device = MagicMock()
    fake_device.attach.return_value = fake_session
    fake_frida = MagicMock()
    fake_frida.get_device.return_value = fake_device
    monkeypatch.setattr(
        "android_mcp.tools.frida_helpers._import_frida",
        lambda: fake_frida,
    )

    handler = _resolve_handler("frida_dump_process_modules")
    result = await handler(device_id="emulator-5554", pid=12345)

    assert result["device_id"] == "emulator-5554"
    assert result["pid"] == 12345
    assert result["modules"] == [
        {
            "name": "libc.so",
            "base": "0x7f1234000000",
            "size": 1_500_000,
            "path": "/system/lib64/libc.so",
        },
        {
            "name": "libssl.so",
            "base": "0x7f1234500000",
            "size": 750_000,
            "path": "/system/lib64/libssl.so",
        },
    ]
    fake_frida.get_device.assert_called_once_with("emulator-5554")
    fake_device.attach.assert_called_once_with(12345)
    fake_session.detach.assert_called_once()


async def test_dump_process_modules_detaches_on_enumerate_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """detach must run even when enumerate_modules raises — leaking a
    frida session on the device blocks subsequent attaches."""

    class _BoomSession:
        detach_called = False

        def enumerate_modules(self) -> list[Any]:
            raise RuntimeError("frida internal blew up")

        def detach(self) -> None:
            _BoomSession.detach_called = True

    fake_device = MagicMock()
    fake_device.attach.return_value = _BoomSession()
    fake_frida = MagicMock()
    fake_frida.get_device.return_value = fake_device
    monkeypatch.setattr(
        "android_mcp.tools.frida_helpers._import_frida",
        lambda: fake_frida,
    )

    handler = _resolve_handler("frida_dump_process_modules")
    with pytest.raises(RuntimeError, match="frida internal blew up"):
        await handler(device_id="local", pid=1)

    assert _BoomSession.detach_called, "session must be detached on enumerate failure"


# ---------------------------------------------------------------------------
# frida_attach_and_trace_calls
# ---------------------------------------------------------------------------


async def test_trace_calls_rejects_zero_duration(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _resolve_handler("frida_attach_and_trace_calls")
    with pytest.raises(ValueError, match="duration_s must be"):
        await handler(device_id="local", pid=1, method_signatures=[], duration_s=0)


async def test_trace_calls_rejects_negative_duration(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _resolve_handler("frida_attach_and_trace_calls")
    with pytest.raises(ValueError, match="duration_s must be"):
        await handler(device_id="local", pid=1, method_signatures=[], duration_s=-5)


async def test_trace_calls_rejects_over_cap_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = _resolve_handler("frida_attach_and_trace_calls")
    with pytest.raises(ValueError, match="duration_s must be"):
        await handler(device_id="local", pid=1, method_signatures=[], duration_s=301)


async def test_trace_calls_full_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock the full session lifecycle and verify the trace payload shape."""
    fake_exports = MagicMock()
    fake_exports.get_traces.return_value = [
        {"signature": "native:libc.so:open", "timestamp_ms": 1_700_000_000_000, "thread": 7},
        {
            "signature": "java:java.lang.String:valueOf",
            "timestamp_ms": 1_700_000_000_050,
            "args": ["hello"],
        },
    ]
    fake_script = MagicMock()
    fake_script.exports_sync = fake_exports
    fake_session = MagicMock()
    fake_session.create_script.return_value = fake_script
    fake_device = MagicMock()
    fake_device.attach.return_value = fake_session
    fake_frida = MagicMock()
    fake_frida.get_device.return_value = fake_device

    monkeypatch.setattr(
        "android_mcp.tools.frida_helpers._import_frida",
        lambda: fake_frida,
    )
    # Skip the actual sleep — test runtime stays under a second.
    monkeypatch.setattr("android_mcp.tools.frida_helpers.time.sleep", lambda _s: None)

    handler = _resolve_handler("frida_attach_and_trace_calls")
    result = await handler(
        device_id="emulator-5554",
        pid=1234,
        method_signatures=[
            "native:libc.so:open",
            "java:java.lang.String:valueOf",
            "garbage-format",
        ],
        duration_s=2,
    )

    assert result["device_id"] == "emulator-5554"
    assert result["pid"] == 1234
    assert result["duration_s"] == 2
    assert result["installed_signatures"] == [
        "native:libc.so:open",
        "java:java.lang.String:valueOf",
    ]
    assert result["skipped_signatures"] == ["garbage-format"]
    assert result["events"] == [
        {"signature": "native:libc.so:open", "timestamp_ms": 1_700_000_000_000, "thread": 7},
        {
            "signature": "java:java.lang.String:valueOf",
            "timestamp_ms": 1_700_000_000_050,
            "args": ["hello"],
        },
    ]

    # The injected script must include both interceptor clauses plus the
    # RPC export. Verify by re-reading the source passed to create_script.
    (script_source,), _ = fake_session.create_script.call_args
    assert "Module.findExportByName" in script_source
    assert "Java.use" in script_source
    assert "rpc.exports" in script_source
    assert "getTraces" in script_source

    fake_session.detach.assert_called_once()


async def test_trace_calls_falls_back_to_exports_when_sync_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Older frida bindings expose `script.exports` rather than
    `script.exports_sync`. The handler must accept both."""
    fake_exports = MagicMock()
    fake_exports.get_traces.return_value = []
    fake_script = MagicMock(spec=["create_script", "load", "exports"])
    fake_script.exports = fake_exports
    fake_session = MagicMock()
    fake_session.create_script.return_value = fake_script
    fake_device = MagicMock()
    fake_device.attach.return_value = fake_session
    fake_frida = MagicMock()
    fake_frida.get_device.return_value = fake_device

    monkeypatch.setattr(
        "android_mcp.tools.frida_helpers._import_frida",
        lambda: fake_frida,
    )
    monkeypatch.setattr("android_mcp.tools.frida_helpers.time.sleep", lambda _s: None)

    handler = _resolve_handler("frida_attach_and_trace_calls")
    result = await handler(
        device_id="local",
        pid=1,
        method_signatures=["native:libc.so:open"],
        duration_s=1,
    )

    assert result["events"] == []
    fake_exports.get_traces.assert_called_once()


# ---------------------------------------------------------------------------
# _build_trace_script + clause helpers
# ---------------------------------------------------------------------------


def test_build_trace_script_partitions_signatures() -> None:
    from android_mcp.tools.frida_helpers import _build_trace_script

    installed, skipped, source = _build_trace_script(
        [
            "native:libc.so:open",
            "java:com.example.Foo:bar",
            "",
            "unknown:prefix:value",
            "native:libssl.so",  # missing third part
            "java:com.example.Foo:bar:extra",  # too many parts
        ],
    )

    assert installed == ["native:libc.so:open", "java:com.example.Foo:bar"]
    assert skipped == [
        "",
        "unknown:prefix:value",
        "native:libssl.so",
        "java:com.example.Foo:bar:extra",
    ]
    assert "var traces = []" in source
    assert "rpc.exports" in source


def test_build_trace_script_empty_signatures() -> None:
    from android_mcp.tools.frida_helpers import _build_trace_script

    installed, skipped, source = _build_trace_script([])
    assert installed == []
    assert skipped == []
    assert "var traces = []" in source
    assert "rpc.exports" in source


def test_native_clause_embeds_signature_module_and_symbol() -> None:
    from android_mcp.tools.frida_helpers import _native_clause

    clause = _native_clause("native:libc.so:open", "libc.so", "open")
    assert '"native:libc.so:open"' in clause
    assert '"libc.so"' in clause
    assert '"open"' in clause
    assert "Module.findExportByName" in clause
    assert "Interceptor.attach" in clause


def test_java_clause_embeds_signature_class_and_method() -> None:
    from android_mcp.tools.frida_helpers import _java_clause

    clause = _java_clause(
        "java:java.lang.String:valueOf",
        "java.lang.String",
        "valueOf",
    )
    assert '"java:java.lang.String:valueOf"' in clause
    assert '"java.lang.String"' in clause
    assert '"valueOf"' in clause
    assert "Java.use" in clause
    assert "method.implementation" in clause


def test_native_clause_quotes_special_characters() -> None:
    """json.dumps must protect against signature/module strings that
    would otherwise break out of the JS string literal."""
    from android_mcp.tools.frida_helpers import _native_clause

    clause = _native_clause('native:lib"quoted":open', 'lib"quoted"', "open")
    # The embedded quote must be escaped — the unescaped form appearing
    # anywhere outside a comment would mean json.dumps was bypassed.
    assert 'lib\\"quoted\\"' in clause
