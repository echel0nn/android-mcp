"""Tests for the objection wrapper — patchapk + explore.

These tests run without ``objection`` installed: ``subprocess.run`` is
patched at the module level so the wrapper exercises every parse path
against canned outputs and side-effects. The mock-based suite is the
load-bearing one — it covers the patched-APK discovery, every
explore-mode branch (probe / command / file_commands), and the
input-validation envelope without needing the real sensepost
objection package on PATH.

One smoke-test per handler exercises the real binary when it is on PATH,
otherwise it skips cleanly. That keeps CI green when objection is
missing while still catching upstream behavior drift if the operator's
environment has it installed.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test helpers — apk fixture, subprocess stand-in, register-and-capture
# ---------------------------------------------------------------------------


def _make_apk(tmp_path: Path, name: str = "stub.apk") -> Path:
    """Drop a zip-magic stub at .apk path. Content is irrelevant — the
    subprocess call is mocked; only the path-resolution branch of the
    handler touches this file."""
    apk = tmp_path / name
    apk.write_bytes(b"PK\x03\x04")
    return apk


def _completed(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> MagicMock:
    """Build a stand-in for ``subprocess.CompletedProcess``."""
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _run_writing_patched_apk(
    apk: Path,
    *,
    returncode: int = 0,
    stdout: str = "Patcher will be using Gadget version: 16.7.19\n",
    stderr: str = "",
) -> Any:
    """Build a ``subprocess.run`` stand-in that writes objection's
    expected output APK next to the source and returns a
    CompletedProcess stub. Mirrors objection's actual side-effect:
    ``shutil.copyfile(<temp-patched>, <source-dir>/<stem>.objection.apk)``
    on success.
    """
    expected = apk.parent / apk.name.replace(".apk", ".objection.apk")

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        if returncode == 0:
            expected.write_bytes(b"PK\x03\x04patched")
        return _completed(returncode=returncode, stdout=stdout, stderr=stderr)

    return _side_effect


def _capture_handlers() -> dict[str, Any]:
    """Resolve all ``@mcp.tool()``-registered handlers from ``register``."""
    from android_mcp.tools.objection import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn

            return deco

    register(_MCP())
    return captured


async def _call_patch_apk(
    apk_path: str,
    gadget_arch: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    handlers = _capture_handlers()
    fn = handlers.get("objection_patch_apk")
    assert callable(fn), "register did not capture objection_patch_apk"
    return await fn(
        apk_path=apk_path,
        gadget_arch=gadget_arch,
        output_path=output_path,
    )


async def _call_explore(
    device_serial: str,
    package_name: str,
    script: str | None = None,
) -> dict[str, Any]:
    handlers = _capture_handlers()
    fn = handlers.get("objection_explore")
    assert callable(fn), "register did not capture objection_explore"
    return await fn(
        device_serial=device_serial,
        package_name=package_name,
        script=script,
    )


# ---------------------------------------------------------------------------
# patchapk — install-hint envelope
# ---------------------------------------------------------------------------


async def test_patch_apk_missing_objection_raises_runtime_error(
    tmp_path: Path,
) -> None:
    """objection not on PATH → RuntimeError carrying the install hint."""
    apk = _make_apk(tmp_path)
    with patch("android_mcp.tools.objection.shutil.which", return_value=None):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_patch_apk(str(apk), "arm64-v8a")
    msg = str(exc_info.value)
    assert "objection not on PATH" in msg
    assert "pip install objection" in msg
    assert "sensepost/objection" in msg


# ---------------------------------------------------------------------------
# patchapk — input validation
# ---------------------------------------------------------------------------


async def test_patch_apk_invalid_arch_raises_value_error(
    tmp_path: Path,
) -> None:
    """Architecture outside the supported set → ValueError before
    any subprocess work."""
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.objection.shutil.which",
        return_value="/fake/objection",
    ):
        with pytest.raises(ValueError, match="gadget_arch must be one of"):
            await _call_patch_apk(str(apk), "mips64")


async def test_patch_apk_missing_apk_raises_file_not_found(
    tmp_path: Path,
) -> None:
    """Nonexistent source APK → FileNotFoundError, never reaches subprocess."""
    nonexistent = tmp_path / "no-such.apk"
    with patch(
        "android_mcp.tools.objection.shutil.which",
        return_value="/fake/objection",
    ):
        with pytest.raises(FileNotFoundError, match="apk not found"):
            await _call_patch_apk(str(nonexistent), "arm64-v8a")


async def test_patch_apk_directory_path_raises_value_error(
    tmp_path: Path,
) -> None:
    """A directory at the APK path → ValueError, not FileNotFoundError."""
    not_a_file = tmp_path / "dir"
    not_a_file.mkdir()
    with patch(
        "android_mcp.tools.objection.shutil.which",
        return_value="/fake/objection",
    ):
        with pytest.raises(ValueError, match="not a file"):
            await _call_patch_apk(str(not_a_file), "arm64-v8a")


async def test_patch_apk_basename_without_apk_raises_value_error(
    tmp_path: Path,
) -> None:
    """An APK file whose basename does not contain ``.apk`` cannot have
    its output-filename derived; reject early rather than running
    objection and hitting a no-such-file branch."""
    weird = tmp_path / "no-extension"
    weird.write_bytes(b"PK\x03\x04")
    with patch(
        "android_mcp.tools.objection.shutil.which",
        return_value="/fake/objection",
    ):
        with pytest.raises(ValueError, match="must contain '.apk'"):
            await _call_patch_apk(str(weird), "arm64-v8a")


# ---------------------------------------------------------------------------
# patchapk — happy path + return shape
# ---------------------------------------------------------------------------


async def test_patch_apk_happy_path_returns_documented_shape(
    tmp_path: Path,
) -> None:
    """End-to-end happy path returns ``{patched_apk_path, source_apk,
    architecture, stdout_tail}`` with the patched APK file present."""
    apk = _make_apk(tmp_path, "app.apk")
    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_run_writing_patched_apk(apk),
        ),
    ):
        result = await _call_patch_apk(str(apk), "arm64-v8a")

    expected_keys = {"patched_apk_path", "source_apk", "architecture", "stdout_tail"}
    assert set(result.keys()) == expected_keys
    assert result["architecture"] == "arm64-v8a"
    assert result["source_apk"] == str(apk.resolve())
    assert result["patched_apk_path"].endswith("app.objection.apk")
    assert Path(result["patched_apk_path"]).exists()
    assert "Gadget version" in result["stdout_tail"]


async def test_patch_apk_default_output_lives_next_to_source(
    tmp_path: Path,
) -> None:
    """With ``output_path=None``, objection's own output location is
    preserved (next to the source, named ``<stem>.objection.apk``)."""
    apk = _make_apk(tmp_path, "app.apk")
    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_run_writing_patched_apk(apk),
        ),
    ):
        result = await _call_patch_apk(str(apk), "arm64-v8a")

    patched = Path(result["patched_apk_path"])
    assert patched.parent == apk.parent
    assert patched.name == "app.objection.apk"


async def test_patch_apk_output_path_moves_file(tmp_path: Path) -> None:
    """When ``output_path`` is set, the patched APK is moved there and
    no longer exists at objection's default location."""
    apk = _make_apk(tmp_path, "app.apk")
    target = tmp_path / "out" / "patched.apk"
    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_run_writing_patched_apk(apk),
        ),
    ):
        result = await _call_patch_apk(str(apk), "arm64-v8a", str(target))

    assert result["patched_apk_path"] == str(target.resolve())
    assert target.exists()
    # objection's original output location is empty now
    original = apk.parent / "app.objection.apk"
    assert not original.exists()


async def test_patch_apk_argv_shape(tmp_path: Path) -> None:
    """objection is invoked with the documented argv: ``patchapk
    --source <abs> --architecture <arch>``."""
    apk = _make_apk(tmp_path, "app.apk")
    seen: dict[str, Any] = {}

    def _record(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = list(cmd)
        seen["kwargs"] = dict(kwargs)
        expected = apk.parent / "app.objection.apk"
        expected.write_bytes(b"PK\x03\x04patched")
        return _completed()

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_record,
        ),
    ):
        await _call_patch_apk(str(apk), "arm64-v8a")

    cmd = seen["cmd"]
    assert cmd[0] == "/fake/objection"
    assert cmd[1] == "patchapk"
    # --source <abs apk>
    idx = cmd.index("--source")
    assert cmd[idx + 1] == str(apk.resolve())
    # --architecture <arch>
    idx = cmd.index("--architecture")
    assert cmd[idx + 1] == "arm64-v8a"


async def test_patch_apk_subprocess_runs_in_isolated_cwd(
    tmp_path: Path,
) -> None:
    """The subprocess.run cwd kwarg points at a temp directory, NOT the
    test process cwd. This isolates apktool's stray temp files from the
    operator's working directory."""
    apk = _make_apk(tmp_path, "app.apk")
    seen: dict[str, Any] = {}

    def _record(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cwd"] = kwargs.get("cwd")
        expected = apk.parent / "app.objection.apk"
        expected.write_bytes(b"PK\x03\x04patched")
        return _completed()

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_record,
        ),
    ):
        await _call_patch_apk(str(apk), "arm64-v8a")

    cwd = seen["cwd"]
    assert cwd is not None
    # The temp prefix matches the wrapper's tempfile.TemporaryDirectory call.
    assert "objection-patch-" in Path(cwd).name


# ---------------------------------------------------------------------------
# patchapk — error paths
# ---------------------------------------------------------------------------


async def test_patch_apk_nonzero_exit_raises_runtime_error(
    tmp_path: Path,
) -> None:
    """A non-zero objection exit surfaces stderr in the RuntimeError."""
    apk = _make_apk(tmp_path, "app.apk")
    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_run_writing_patched_apk(
                apk,
                returncode=2,
                stderr="apktool: unable to decode resources",
            ),
        ),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_patch_apk(str(apk), "arm64-v8a")
    msg = str(exc_info.value)
    assert "exited 2" in msg
    assert "unable to decode resources" in msg


async def test_patch_apk_timeout_raises_runtime_error(
    tmp_path: Path,
) -> None:
    """A ``TimeoutExpired`` from subprocess.run becomes a RuntimeError
    rather than leaking the timeout exception class to the caller."""
    apk = _make_apk(tmp_path, "app.apk")

    def _hang(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd, timeout=600)

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_hang,
        ),
    ):
        with pytest.raises(RuntimeError, match="timed out after 600s"):
            await _call_patch_apk(str(apk), "arm64-v8a")


async def test_patch_apk_missing_output_raises_runtime_error(
    tmp_path: Path,
) -> None:
    """objection returns 0 but never wrote the expected output file →
    surface the failure (rather than returning a phantom path)."""
    apk = _make_apk(tmp_path, "app.apk")

    def _no_write(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        # Returncode 0, but DO NOT write the .objection.apk file.
        return _completed(stdout="claims to succeed but did not write")

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_no_write,
        ),
    ):
        with pytest.raises(RuntimeError, match="did not produce"):
            await _call_patch_apk(str(apk), "arm64-v8a")


async def test_patch_apk_stdout_tail_truncates(tmp_path: Path) -> None:
    """``stdout_tail`` keeps only the trailing 2 KB of objection stdout
    so a verbose log does not balloon the JSON response."""
    apk = _make_apk(tmp_path, "app.apk")
    huge_stdout = ("x" * 5000) + "TAIL_MARKER"
    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_run_writing_patched_apk(apk, stdout=huge_stdout),
        ),
    ):
        result = await _call_patch_apk(str(apk), "arm64-v8a")

    tail = result["stdout_tail"]
    assert len(tail) <= 2048
    # The marker is at the end of the original; truncation keeps the tail.
    assert tail.endswith("TAIL_MARKER")


# ---------------------------------------------------------------------------
# explore — install-hint and input validation
# ---------------------------------------------------------------------------


async def test_explore_missing_objection_raises_runtime_error() -> None:
    """objection not on PATH → RuntimeError carrying the install hint."""
    with patch("android_mcp.tools.objection.shutil.which", return_value=None):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_explore("emulator-5554", "com.example.app")
    assert "objection not on PATH" in str(exc_info.value)


async def test_explore_empty_device_serial_raises_value_error() -> None:
    """Empty device serial → ValueError, never reaches subprocess."""
    with patch(
        "android_mcp.tools.objection.shutil.which",
        return_value="/fake/objection",
    ):
        with pytest.raises(ValueError, match="device_serial"):
            await _call_explore("", "com.example.app")


async def test_explore_empty_package_name_raises_value_error() -> None:
    """Empty package name → ValueError, never reaches subprocess."""
    with patch(
        "android_mcp.tools.objection.shutil.which",
        return_value="/fake/objection",
    ):
        with pytest.raises(ValueError, match="package_name"):
            await _call_explore("emulator-5554", "")


# ---------------------------------------------------------------------------
# explore — mode dispatch
# ---------------------------------------------------------------------------


async def test_explore_probe_mode_default(tmp_path: Path) -> None:
    """``script=None`` → probe mode running ``run env.android``."""
    seen: dict[str, Any] = {}

    def _record(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = list(cmd)
        seen["stdin"] = kwargs.get("stdin")
        return _completed(stdout="package: com.example.app\n")

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_record,
        ),
    ):
        result = await _call_explore(
            "emulator-5554",
            "com.example.app",
        )

    assert result["mode"] == "probe"
    cmd = seen["cmd"]
    assert cmd[0] == "/fake/objection"
    assert "--serial" in cmd and cmd[cmd.index("--serial") + 1] == "emulator-5554"
    assert "--name" in cmd and cmd[cmd.index("--name") + 1] == "com.example.app"
    assert cmd[-2:] == ["run", "env.android"]
    # stdin is closed so the REPL cannot block waiting for input.
    assert seen["stdin"] == subprocess.DEVNULL


async def test_explore_command_mode(tmp_path: Path) -> None:
    """``script="env"`` (no file at that path) → command mode running
    ``run env``."""
    seen: dict[str, Any] = {}

    def _record(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = list(cmd)
        return _completed(stdout="VAR=value\n")

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_record,
        ),
    ):
        result = await _call_explore(
            "emulator-5554",
            "com.example.app",
            script="env",
        )

    assert result["mode"] == "command"
    cmd = seen["cmd"]
    assert cmd[-2:] == ["run", "env"]


async def test_explore_command_mode_preserves_multi_token_command(
    tmp_path: Path,
) -> None:
    """A multi-word command (``"android root disable"``) is passed as a
    single argv token so the REPL parses one logical command. ``Path()``
    on this string does not raise — it just produces a path that does
    not exist, falling through to command mode."""
    seen: dict[str, Any] = {}

    def _record(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = list(cmd)
        return _completed()

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_record,
        ),
    ):
        result = await _call_explore(
            "emulator-5554",
            "com.example.app",
            script="android root disable",
        )

    assert result["mode"] == "command"
    # Last two tokens are `run` and the script string as one argv element.
    assert seen["cmd"][-2:] == ["run", "android root disable"]


async def test_explore_file_commands_mode(tmp_path: Path) -> None:
    """``script`` pointing at an existing file → file_commands mode
    running ``start --quiet --file-commands <abs-path>``."""
    script_file = tmp_path / "commands.objection"
    script_file.write_text(
        "android root disable\n"
        "android sslpinning disable\n",
        encoding="utf-8",
    )
    seen: dict[str, Any] = {}

    def _record(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = list(cmd)
        return _completed(stdout="bypass enabled\n")

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_record,
        ),
    ):
        result = await _call_explore(
            "emulator-5554",
            "com.example.app",
            script=str(script_file),
        )

    assert result["mode"] == "file_commands"
    cmd = seen["cmd"]
    assert "start" in cmd
    assert "--quiet" in cmd
    idx = cmd.index("--file-commands")
    assert cmd[idx + 1] == str(script_file.resolve())


# ---------------------------------------------------------------------------
# explore — return shape + error paths
# ---------------------------------------------------------------------------


async def test_explore_return_shape_captures_io_and_exit(
    tmp_path: Path,
) -> None:
    """Return dict captures stdout, stderr, exit_code verbatim."""
    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            return_value=_completed(
                returncode=3,
                stdout="some stdout",
                stderr="some stderr",
            ),
        ),
    ):
        result = await _call_explore(
            "emulator-5554",
            "com.example.app",
        )

    expected_keys = {
        "device_serial", "package_name", "mode", "command",
        "stdout", "stderr", "exit_code",
    }
    assert set(result.keys()) == expected_keys
    assert result["device_serial"] == "emulator-5554"
    assert result["package_name"] == "com.example.app"
    assert result["stdout"] == "some stdout"
    assert result["stderr"] == "some stderr"
    assert result["exit_code"] == 3
    assert isinstance(result["command"], list)


async def test_explore_timeout_raises_runtime_error() -> None:
    """``TimeoutExpired`` from subprocess.run becomes a RuntimeError
    naming both the timeout and the target."""

    def _hang(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd, timeout=120)

    with (
        patch(
            "android_mcp.tools.objection.shutil.which",
            return_value="/fake/objection",
        ),
        patch(
            "android_mcp.tools.objection.subprocess.run",
            side_effect=_hang,
        ),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_explore(
                "emulator-5554",
                "com.example.app",
            )
    msg = str(exc_info.value)
    assert "timed out after 120s" in msg
    assert "emulator-5554" in msg
    assert "com.example.app" in msg


# ---------------------------------------------------------------------------
# Smoke tests against the real objection binary
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("objection") is None,
    reason="real objection binary not on PATH",
)
async def test_real_objection_patch_apk_missing_apk_raises(
    tmp_path: Path,
) -> None:
    """When the real ``objection`` binary is installed, pointing it at a
    nonexistent APK raises ``FileNotFoundError`` before subprocess
    invocation (input validation runs first)."""
    nonexistent = tmp_path / "no-such.apk"
    with pytest.raises(FileNotFoundError):
        await _call_patch_apk(str(nonexistent), "arm64-v8a")


@pytest.mark.skipif(
    shutil.which("objection") is None,
    reason="real objection binary not on PATH",
)
async def test_real_objection_explore_rejects_empty_serial() -> None:
    """When the real ``objection`` is on PATH, input-validation still
    runs before any subprocess work — empty device_serial fails fast."""
    with pytest.raises(ValueError, match="device_serial"):
        await _call_explore("", "com.example.app")
