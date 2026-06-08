"""Tests for the adb facade — devices / install / uninstall / logcat / dumpsys.

`adb` is a host CLI talking to a per-device adbd daemon. None of the
tests below need a real device: `subprocess.run` is patched at the
module level to return canned adb output, and `shutil.which` is
patched to make the missing-binary path testable.

The mock suite is the load-bearing one — it covers the device-list
parser, the install/uninstall success-marker logic, the logcat
timeout-as-termination idiom, and every validation envelope. One
end-to-end smoke test runs when `adb` is on PATH and skips cleanly
otherwise.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _completed(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> MagicMock:
    """Build a stand-in for `subprocess.CompletedProcess`."""
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _resolve_handler(name: str) -> Any:
    """Run `register(_MCP())` and return the named handler.

    Five tools register through one `register()` call, so the helper
    captures by name into a shared dict and returns the requested one.
    """
    from android_mcp.tools.adb import register

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


# ---------------------------------------------------------------------------
# install-hint envelope — applies uniformly to every handler
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "handler_name, args, kwargs",
    [
        ("adb_devices", (), {}),
        ("adb_install", (), {"device_serial": "x", "apk_path": "/tmp/x.apk"}),
        ("adb_uninstall", (), {"device_serial": "x", "package_name": "com.x"}),
        ("adb_logcat_capture", (), {"device_serial": "x", "duration_s": 1}),
        ("adb_dumpsys", (), {"device_serial": "x", "service": "activity"}),
    ],
)
async def test_handlers_raise_install_hint_when_adb_missing(
    handler_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Every handler emits the same install hint when `adb` is not on PATH."""
    fn = _resolve_handler(handler_name)
    with patch("android_mcp.tools.adb.shutil.which", return_value=None):
        with pytest.raises(RuntimeError) as exc_info:
            await fn(*args, **kwargs)
    assert "adb not on PATH" in str(exc_info.value)
    assert "platform-tools" in str(exc_info.value)


# ---------------------------------------------------------------------------
# adb_devices — parser correctness
# ---------------------------------------------------------------------------


_DEVICES_STANDARD = """\
List of devices attached
emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64x transport_id:1
ABCD1234567890         device usb:1-1 product:cheetah model:Pixel_7_Pro device:cheetah transport_id:2
"""


_DEVICES_MIXED_STATES = """\
List of devices attached
emulator-5554          device product:sdk_gphone64_x86_64 model:sdk model:sdk device:emu64x transport_id:1
1A2B3C                 unauthorized usb:2-1 transport_id:3
xx.xx.xx.xx:5555       offline transport_id:4
"""


_DEVICES_WITH_BANNER = """\
* daemon not running; starting now at tcp:5037
* daemon started successfully
List of devices attached
emulator-5554          device transport_id:1
"""


_DEVICES_EMPTY = "List of devices attached\n\n"


_DEVICES_WITH_UNKNOWN_KEY = """\
List of devices attached
emulator-5554          device product:foo extra_field:bar transport_id:9
"""


async def test_adb_devices_parses_standard_two_device_output() -> None:
    """Long-format output yields one structured row per device with
    every known key extracted."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout=_DEVICES_STANDARD),
        ),
    ):
        result = await fn()
    assert len(result["devices"]) == 2
    emu, phone = result["devices"]
    assert emu["serial"] == "emulator-5554"
    assert emu["state"] == "device"
    assert emu["product"] == "sdk_gphone64_x86_64"
    assert emu["transport_id"] == "1"
    assert emu["usb"] == ""  # no usb token for the emulator
    assert phone["serial"] == "ABCD1234567890"
    assert phone["usb"] == "1-1"
    assert phone["model"] == "Pixel_7_Pro"


async def test_adb_devices_parses_mixed_states() -> None:
    """`unauthorized` and `offline` rows surface with empty metadata
    fields when adb omits them."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout=_DEVICES_MIXED_STATES),
        ),
    ):
        result = await fn()
    states = [d["state"] for d in result["devices"]]
    assert states == ["device", "unauthorized", "offline"]
    # Unauthorized + offline devices typically lack product/model — we
    # carry empty strings for them rather than dropping the row.
    assert result["devices"][1]["product"] == ""
    assert result["devices"][2]["transport_id"] == "4"


async def test_adb_devices_skips_server_start_banner() -> None:
    """`* daemon ...` lines that adb prints when starting the server
    are skipped without polluting the device list."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout=_DEVICES_WITH_BANNER),
        ),
    ):
        result = await fn()
    assert len(result["devices"]) == 1
    assert result["devices"][0]["serial"] == "emulator-5554"


async def test_adb_devices_empty_list() -> None:
    """No devices attached returns an empty list, not an error."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout=_DEVICES_EMPTY),
        ),
    ):
        result = await fn()
    assert result == {"devices": []}


async def test_adb_devices_preserves_unknown_metadata_in_extras() -> None:
    """Forward-compat: unknown `key:value` tokens land in `extras`
    rather than being silently dropped."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout=_DEVICES_WITH_UNKNOWN_KEY),
        ),
    ):
        result = await fn()
    [row] = result["devices"]
    assert row["extras"] == {"extra_field": "bar"}
    assert row["product"] == "foo"


async def test_adb_devices_raises_on_nonzero_exit() -> None:
    """`devices` exiting non-zero means the local adb server itself is
    broken — surface a RuntimeError rather than returning empty."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(
                returncode=1,
                stdout="",
                stderr="cannot bind 'tcp:5037'",
            ),
        ),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await fn()
    assert "adb devices" in str(exc_info.value)
    assert "cannot bind" in str(exc_info.value)


async def test_adb_devices_timeout_becomes_runtime_error() -> None:
    """Subprocess timeout maps to a RuntimeError with a clean message."""
    fn = _resolve_handler("adb_devices")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["adb"], timeout=30),
        ),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await fn()
    assert "timed out after 30s" in str(exc_info.value)


# ---------------------------------------------------------------------------
# adb_install — success-marker logic + validation
# ---------------------------------------------------------------------------


def _make_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "stub.apk"
    apk.write_bytes(b"PK\x03\x04")
    return apk


async def test_adb_install_success_path(tmp_path: Path) -> None:
    """Exit 0 + "Success" in stdout sets `success=True`."""
    apk = _make_apk(tmp_path)
    fn = _resolve_handler("adb_install")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout="Performing Streamed Install\nSuccess\n"),
        ),
    ):
        result = await fn(device_serial="emulator-5554", apk_path=str(apk))
    assert result["success"] is True
    assert result["device_serial"] == "emulator-5554"
    assert result["apk_path"] == str(apk.resolve())
    assert result["exit_code"] == 0


async def test_adb_install_failure_path(tmp_path: Path) -> None:
    """Exit non-zero OR no "Success" token in stdout sets `success=False`."""
    apk = _make_apk(tmp_path)
    fn = _resolve_handler("adb_install")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(
                returncode=1,
                stdout="adb: failed to install /tmp/stub.apk: ...\n",
                stderr="INSTALL_FAILED_INSUFFICIENT_STORAGE",
            ),
        ),
    ):
        result = await fn(device_serial="emulator-5554", apk_path=str(apk))
    assert result["success"] is False
    assert result["exit_code"] == 1
    assert "INSTALL_FAILED" in result["stderr"]


async def test_adb_install_treats_missing_marker_as_failure(tmp_path: Path) -> None:
    """adb has shipped at least one bug where exit code lied about
    install outcome — absence of "Success" overrides exit code 0."""
    apk = _make_apk(tmp_path)
    fn = _resolve_handler("adb_install")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(
                returncode=0,
                stdout="adb: failed to install... ambiguous\n",
            ),
        ),
    ):
        result = await fn(device_serial="emulator-5554", apk_path=str(apk))
    assert result["success"] is False


async def test_adb_install_rejects_missing_apk(tmp_path: Path) -> None:
    """Missing APK path raises FileNotFoundError before invoking adb."""
    fn = _resolve_handler("adb_install")
    nonexistent = tmp_path / "ghost.apk"
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch("android_mcp.tools.adb.subprocess.run") as run_mock,
    ):
        with pytest.raises(FileNotFoundError):
            await fn(device_serial="emulator-5554", apk_path=str(nonexistent))
    run_mock.assert_not_called()


async def test_adb_install_rejects_directory_apk(tmp_path: Path) -> None:
    """A directory at the APK path is rejected with ValueError."""
    fn = _resolve_handler("adb_install")
    a_dir = tmp_path / "not_an_apk"
    a_dir.mkdir()
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError, match="not a file"):
            await fn(device_serial="emulator-5554", apk_path=str(a_dir))


async def test_adb_install_rejects_empty_device_serial(tmp_path: Path) -> None:
    """Empty `device_serial` raises ValueError before any subprocess
    invocation — implicit single-device behavior is the bug the
    acceptance criterion exists to prevent."""
    apk = _make_apk(tmp_path)
    fn = _resolve_handler("adb_install")
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError, match="device_serial is required"):
            await fn(device_serial="", apk_path=str(apk))
        with pytest.raises(ValueError, match="device_serial is required"):
            await fn(device_serial="   ", apk_path=str(apk))


# ---------------------------------------------------------------------------
# adb_uninstall — success-marker logic
# ---------------------------------------------------------------------------


async def test_adb_uninstall_success_path() -> None:
    """`Success` on stdout sets `success=True`."""
    fn = _resolve_handler("adb_uninstall")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout="Success\n"),
        ),
    ):
        result = await fn(
            device_serial="emulator-5554",
            package_name="com.vodafone.selfservis",
        )
    assert result["success"] is True
    assert result["package_name"] == "com.vodafone.selfservis"


async def test_adb_uninstall_failure_marker() -> None:
    """`Failure [reason]` keeps `success=False` even when exit is 0."""
    fn = _resolve_handler("adb_uninstall")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout="Failure [DELETE_FAILED_INTERNAL_ERROR]\n"),
        ),
    ):
        result = await fn(device_serial="emulator-5554", package_name="com.x")
    assert result["success"] is False
    assert "Failure" in result["stdout"]


async def test_adb_uninstall_rejects_empty_package_name() -> None:
    """Empty package_name raises ValueError up front."""
    fn = _resolve_handler("adb_uninstall")
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError, match="package_name is required"):
            await fn(device_serial="emulator-5554", package_name="")


# ---------------------------------------------------------------------------
# adb_logcat_capture — timeout-as-termination idiom + clear-buffer + filter
# ---------------------------------------------------------------------------


_LOGCAT_SAMPLE = (
    "06-08 03:12:45.123  1234  1234 I MainActivity: onCreate\n"
    "06-08 03:12:45.456  1234  1235 D OkHttp: --> GET https://example.com/api/v1\n"
    "06-08 03:12:45.789  1234  1234 W ActivityManager: warning text\n"
)


def _logcat_side_effect(captured: str = _LOGCAT_SAMPLE) -> Any:
    """Build a `subprocess.run` side effect that:
    - returns `Success` for the `logcat -c` clear step
    - raises TimeoutExpired with the canned stdout for the capture step

    Two-call mock keeps the test honest: clear must run first and must
    succeed before the capture step proceeds.
    """
    call_count = {"n": 0}

    def _side(cmd: list[str], **_: Any) -> MagicMock:
        call_count["n"] += 1
        # First call: the clear-buffer step. adb returns no output on
        # success; exit 0 is enough.
        if "-c" in cmd and call_count["n"] == 1:
            return _completed(stdout="")
        # Second call: the streaming capture. logcat naturally runs
        # forever, so subprocess.run raises TimeoutExpired carrying
        # whatever stdout was buffered when SIGKILL hit.
        raise subprocess.TimeoutExpired(
            cmd=cmd,
            timeout=30,
            output=captured,
            stderr="",
        )

    return _side


async def test_adb_logcat_capture_returns_buffered_lines_on_timeout() -> None:
    """The expected path: subprocess hits the duration cap, exception's
    `.stdout` is the answer, lines are split and stripped of blanks."""
    fn = _resolve_handler("adb_logcat_capture")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch("android_mcp.tools.adb.subprocess.run", side_effect=_logcat_side_effect()),
    ):
        result = await fn(device_serial="emulator-5554", duration_s=1)
    assert result["line_count"] == 3
    assert result["duration_s"] == 1
    assert result["filter_tag"] is None
    assert "MainActivity" in result["lines"][0]
    assert "OkHttp" in result["lines"][1]


async def test_adb_logcat_capture_applies_filter_tag() -> None:
    """`filter_tag` becomes `-s <tag>:*` in the streaming command."""
    fn = _resolve_handler("adb_logcat_capture")
    seen_cmds: list[list[str]] = []

    def _capture_then_timeout(cmd: list[str], **_: Any) -> MagicMock:
        seen_cmds.append(list(cmd))
        if "-c" in cmd and len(seen_cmds) == 1:
            return _completed(stdout="")
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1, output="", stderr="")

    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch("android_mcp.tools.adb.subprocess.run", side_effect=_capture_then_timeout),
    ):
        result = await fn(
            device_serial="emulator-5554",
            duration_s=1,
            filter_tag="OkHttp",
        )
    # Streaming command (second call) carries the filter spec.
    streaming = seen_cmds[1]
    assert "-s" in streaming
    assert "OkHttp:*" in streaming
    assert result["filter_tag"] == "OkHttp"
    assert result["line_count"] == 0


async def test_adb_logcat_capture_raises_when_logcat_exits_early() -> None:
    """If logcat exits inside the window (transport dropped), the
    handler raises rather than returning a too-short window
    silently."""
    fn = _resolve_handler("adb_logcat_capture")

    def _exit_early(cmd: list[str], **_: Any) -> MagicMock:
        # Clear step succeeds, streaming step returns prematurely.
        if "-c" in cmd:
            return _completed(stdout="")
        return _completed(
            returncode=1,
            stdout="",
            stderr="error: device 'emulator-5554' not found",
        )

    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch("android_mcp.tools.adb.subprocess.run", side_effect=_exit_early),
    ):
        with pytest.raises(RuntimeError, match="exited unexpectedly"):
            await fn(device_serial="emulator-5554", duration_s=2)


async def test_adb_logcat_capture_propagates_clear_buffer_failure() -> None:
    """If `logcat -c` fails (transport gone before capture starts),
    the handler raises and never starts the streaming subprocess."""
    fn = _resolve_handler("adb_logcat_capture")

    def _clear_fails(cmd: list[str], **_: Any) -> MagicMock:
        return _completed(returncode=1, stderr="no devices/emulators found")

    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch("android_mcp.tools.adb.subprocess.run", side_effect=_clear_fails),
    ):
        with pytest.raises(RuntimeError, match="adb logcat -c"):
            await fn(device_serial="emulator-5554", duration_s=1)


async def test_adb_logcat_capture_rejects_duration_out_of_range() -> None:
    """`duration_s` outside (0, 300] raises ValueError up front."""
    fn = _resolve_handler("adb_logcat_capture")
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError, match="duration_s"):
            await fn(device_serial="emulator-5554", duration_s=0)
        with pytest.raises(ValueError, match="duration_s"):
            await fn(device_serial="emulator-5554", duration_s=301)


# ---------------------------------------------------------------------------
# adb_dumpsys — service forwarding + validation
# ---------------------------------------------------------------------------


_DUMPSYS_BATTERY = """\
Current Battery Service state:
  AC powered: false
  USB powered: true
  level: 87
  scale: 100
  temperature: 273
"""


async def test_adb_dumpsys_returns_service_output() -> None:
    """dumpsys stdout is returned verbatim — the caller parses
    service-specific formats."""
    fn = _resolve_handler("adb_dumpsys")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(stdout=_DUMPSYS_BATTERY),
        ),
    ):
        result = await fn(device_serial="emulator-5554", service="battery")
    assert result["service"] == "battery"
    assert "level: 87" in result["output"]
    assert result["exit_code"] == 0


async def test_adb_dumpsys_forwards_multi_word_service_arg() -> None:
    """`"package com.vodafone.selfservis"` reaches adb shell as one
    string, matching how operators run dumpsys at a shell prompt."""
    fn = _resolve_handler("adb_dumpsys")
    seen_cmd: list[str] = []

    def _capture(cmd: list[str], **_: Any) -> MagicMock:
        seen_cmd.extend(cmd)
        return _completed(stdout="")

    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch("android_mcp.tools.adb.subprocess.run", side_effect=_capture),
    ):
        await fn(device_serial="emulator-5554", service="package com.vodafone.selfservis")
    assert "shell" in seen_cmd
    # The dumpsys argument is one shell-side string.
    assert "dumpsys package com.vodafone.selfservis" in seen_cmd


async def test_adb_dumpsys_surfaces_nonzero_exit_in_payload() -> None:
    """Some dumpsys services exit non-zero even on a valid dump
    (notably `package` for unknown pkgs). Caller sees exit_code; we
    do not raise."""
    fn = _resolve_handler("adb_dumpsys")
    with (
        patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"),
        patch(
            "android_mcp.tools.adb.subprocess.run",
            return_value=_completed(
                returncode=1,
                stdout="dumpsys failed: package not found\n",
                stderr="",
            ),
        ),
    ):
        result = await fn(device_serial="emulator-5554", service="package com.ghost")
    assert result["exit_code"] == 1
    assert "package not found" in result["output"]


async def test_adb_dumpsys_rejects_empty_service() -> None:
    """Empty service raises ValueError up front."""
    fn = _resolve_handler("adb_dumpsys")
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError, match="service is required"):
            await fn(device_serial="emulator-5554", service="")


# ---------------------------------------------------------------------------
# timeout-range validation — shared envelope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", [0, -1, 301, 1000])
async def test_timeout_out_of_range_rejected(bad_value: int) -> None:
    """All non-logcat handlers reject `timeout_s` outside (0, 300]."""
    fn = _resolve_handler("adb_devices")
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError, match="timeout_s"):
            await fn(timeout_s=bad_value)


@pytest.mark.parametrize("bad_value", ["30", 30.5, True])
async def test_timeout_wrong_type_rejected(bad_value: Any) -> None:
    """Non-int timeouts (including bool, str, float) are rejected.
    bool is an int subclass — explicit guard rules it out so callers
    don't accidentally pass True/False."""
    fn = _resolve_handler("adb_devices")
    with patch("android_mcp.tools.adb.shutil.which", return_value="/usr/bin/adb"):
        with pytest.raises(ValueError):
            await fn(timeout_s=bad_value)


# ---------------------------------------------------------------------------
# real-binary smoke — only runs when adb is on PATH
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("adb") is None,
    reason="adb binary not on PATH",
)
async def test_real_adb_devices_returns_dict() -> None:
    """Smoke test: real `adb devices` returns the expected shape even
    when no devices are attached. Skips cleanly on hosts without adb
    so CI doesn't fail on a missing optional tool."""
    fn = _resolve_handler("adb_devices")
    result = await fn()
    assert "devices" in result
    assert isinstance(result["devices"], list)
    # Every device row (if any) carries the canonical key set.
    for row in result["devices"]:
        for key in ("serial", "state", "product", "model", "transport_id"):
            assert key in row, f"missing key {key} in {row!r}"
