"""Tests for the drozer wrapper — component + scanner audit.

drozer is a host CLI that talks to an on-device agent over TCP. None of
the tests below need either half: `subprocess.run` is patched at the
module level to return canned drozer output, and `shutil.which` is
patched to make the missing-binary path testable. One smoke-test
exercises the real `drozer` binary when it is on PATH and an agent
session is reachable, otherwise it skips cleanly.

The mock-based suite is the load-bearing one — it covers the three
parsers (attacksurface, provider-injection, activity-browsable) and the
install-hint / timeout / connection-error envelopes without depending
on a particular drozer version.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _make_apk(tmp_path: Path) -> Path:
    """Place a zip-magic stub at .apk path. Content is irrelevant because
    the package name comes through `package_name=` in every mock-driven
    test; the file only exists so the FileNotFoundError branch can be
    exercised separately."""
    apk = tmp_path / "stub.apk"
    apk.write_bytes(b"PK\x03\x04")
    return apk


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


async def _call_scan(
    apk_path: str,
    package_name: str | None = None,
) -> dict[str, Any]:
    """Resolve the registered `drozer_scan_apk` handler and call it."""
    from android_mcp.tools.drozer import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture drozer_scan_apk"
    return await fn(apk_path=apk_path, package_name=package_name)


def _by_call_args(*outputs: str) -> Any:
    """Build a `subprocess.run` side-effect that returns canned stdout
    keyed by which command is being invoked.

    drozer_scan_apk fires three calls in fixed order:
        1. `run app.package.attacksurface <pkg>`
        2. `run scanner.provider.injection -a <pkg>`
        3. `run scanner.activity.browsable -a <pkg>`

    The helper takes the three stdout blobs in that order and returns a
    callable that picks the right one based on the `-c` argument in the
    invocation. Anything unrecognized falls back to empty stdout — keeps
    a failing test honest instead of masking a stray fourth call.
    """
    attack, provider, browsable = outputs

    def _side_effect(cmd: list[str], **_: Any) -> MagicMock:
        if "-c" not in cmd:
            return _completed(stdout="")
        idx = cmd.index("-c") + 1
        command = cmd[idx] if idx < len(cmd) else ""
        if "app.package.attacksurface" in command:
            return _completed(stdout=attack)
        if "scanner.provider.injection" in command:
            return _completed(stdout=provider)
        if "scanner.activity.browsable" in command:
            return _completed(stdout=browsable)
        return _completed(stdout="")

    return _side_effect


# ---------------------------------------------------------------------------
# Canned drozer outputs. Each block is hand-built to match what an actual
# drozer console session emits; the parser must tolerate the layout drift
# across versions (singular vs plural component counts, "broadcast
# receivers" vs "receivers").
# ---------------------------------------------------------------------------


_ATTACKSURFACE_TYPICAL = """\
Selecting com.example.target (Example Target 1.0)
Attack Surface:
  3 activities exported
  1 broadcast receivers exported
  2 content providers exported
  0 services exported
  is debuggable
"""

_ATTACKSURFACE_NOT_DEBUGGABLE = """\
Attack Surface:
  5 activities exported
  0 receivers exported
  0 providers exported
  4 services exported
"""

_ATTACKSURFACE_SINGULAR = """\
Attack Surface:
  1 activity exported
  1 broadcast receiver exported
  1 content provider exported
  1 service exported
  is debuggable
"""

_PROVIDER_INJECTION_TYPICAL = """\
Scanning com.example.target...
Not Vulnerable:
  content://com.example.target.safe/items
Injection in Projection:
  content://com.example.target.unsafe/users
  content://com.example.target.unsafe/orders
Injection in Selection:
  content://com.example.target.unsafe/orders
"""

_PROVIDER_INJECTION_CLEAN = """\
Scanning com.example.target...
Not Vulnerable:
  content://com.example.target.safe/items
  content://com.example.target.safe/items2
"""

_BROWSABLE_TYPICAL = """\
Package: com.example.target
  Invocable URIs:
    example://path/foo
    https://example.com/redirect
  Classes:
    com.example.target.MainActivity
    com.example.target.RedirectActivity
"""

_BROWSABLE_EMPTY = """\
Package: com.example.target
  Invocable URIs:
  Classes:
"""

_CONNECT_FAILURE_STDERR = (
    "Error: Could not connect to the drozer Server at 127.0.0.1:31415\n"
)


# ---------------------------------------------------------------------------
# Install-hint envelope
# ---------------------------------------------------------------------------


async def test_missing_drozer_raises_runtime_error(tmp_path: Path) -> None:
    """`drozer` not on PATH → RuntimeError carrying the install hint."""
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.drozer.shutil.which",
        return_value=None,
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_scan(str(apk), package_name="com.example.target")
    assert "drozer not on PATH" in str(exc_info.value)
    assert "pip install drozer" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Happy path — every parser exercised end-to-end
# ---------------------------------------------------------------------------


async def test_full_shape_returned(tmp_path: Path) -> None:
    """End-to-end happy path returns the documented shape."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.drozer.shutil.which",
            return_value="/fake/drozer",
        ),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_TYPICAL,
                _PROVIDER_INJECTION_TYPICAL,
                _BROWSABLE_TYPICAL,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    assert result["package"] == "com.example.target"
    # Counts and debug flag from the attacksurface block.
    exported = result["exported_components"]
    assert exported == {
        "activities": 3,
        "receivers": 1,
        "providers": 2,
        "services": 0,
        "is_debuggable": True,
    }
    # Finder results: two provider-injection findings, two browsable URIs.
    finders = result["finder_results"]
    assert isinstance(finders["provider_injection"], list)
    assert isinstance(finders["activity_browsable"], list)


async def test_provider_injection_partitions_by_vector(tmp_path: Path) -> None:
    """Findings under `Injection in Projection` get vector=projection;
    findings under `Injection in Selection` get vector=selection."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_TYPICAL,
                _PROVIDER_INJECTION_TYPICAL,
                _BROWSABLE_TYPICAL,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    pi = result["finder_results"]["provider_injection"]
    projection = [f for f in pi if f["vector"] == "projection"]
    selection = [f for f in pi if f["vector"] == "selection"]
    assert len(projection) == 2
    assert {f["uri"] for f in projection} == {
        "content://com.example.target.unsafe/users",
        "content://com.example.target.unsafe/orders",
    }
    assert len(selection) == 1
    assert selection[0]["uri"] == "content://com.example.target.unsafe/orders"


async def test_provider_injection_drops_not_vulnerable(tmp_path: Path) -> None:
    """`Not Vulnerable:` URIs do NOT appear in the findings list — only
    actual vulnerabilities are surfaced."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_TYPICAL,
                _PROVIDER_INJECTION_CLEAN,
                _BROWSABLE_TYPICAL,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    assert result["finder_results"]["provider_injection"] == []


async def test_activity_browsable_extracts_uris_and_classes(
    tmp_path: Path,
) -> None:
    """Each browsable block surfaces its invocable URIs and class list."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_TYPICAL,
                _PROVIDER_INJECTION_TYPICAL,
                _BROWSABLE_TYPICAL,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    browsable = result["finder_results"]["activity_browsable"]
    assert len(browsable) == 1
    entry = browsable[0]
    assert entry["package"] == "com.example.target"
    assert entry["invocable_uris"] == [
        "example://path/foo",
        "https://example.com/redirect",
    ]
    assert entry["classes"] == [
        "com.example.target.MainActivity",
        "com.example.target.RedirectActivity",
    ]


async def test_activity_browsable_empty_block(tmp_path: Path) -> None:
    """A `Package:` block with empty URI/Classes subsections still yields
    one entry with two empty lists — the package is registered as
    browsable-clean rather than dropped."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_TYPICAL,
                _PROVIDER_INJECTION_CLEAN,
                _BROWSABLE_EMPTY,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    browsable = result["finder_results"]["activity_browsable"]
    assert browsable == [
        {
            "package": "com.example.target",
            "invocable_uris": [],
            "classes": [],
        },
    ]


# ---------------------------------------------------------------------------
# Parser tolerance for drozer version drift
# ---------------------------------------------------------------------------


async def test_attacksurface_not_debuggable_flag(tmp_path: Path) -> None:
    """A missing `is debuggable` line resolves to `is_debuggable=False`,
    and "receivers" (no "broadcast " prefix) is still recognized."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_NOT_DEBUGGABLE,
                _PROVIDER_INJECTION_CLEAN,
                _BROWSABLE_EMPTY,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    assert result["exported_components"] == {
        "activities": 5,
        "receivers": 0,
        "providers": 0,
        "services": 4,
        "is_debuggable": False,
    }


async def test_attacksurface_singular_forms_accepted(tmp_path: Path) -> None:
    """`1 activity exported` / `1 broadcast receiver exported` / etc. are
    parsed identically to the plural forms."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_SINGULAR,
                _PROVIDER_INJECTION_CLEAN,
                _BROWSABLE_EMPTY,
            ),
        ),
    ):
        result = await _call_scan(str(apk), package_name="com.example.target")

    assert result["exported_components"] == {
        "activities": 1,
        "receivers": 1,
        "providers": 1,
        "services": 1,
        "is_debuggable": True,
    }


# ---------------------------------------------------------------------------
# Connection / timeout / non-zero-exit envelopes
# ---------------------------------------------------------------------------


async def test_connection_failure_becomes_runtime_error(tmp_path: Path) -> None:
    """An on-device-agent-not-reachable error is translated to a clean
    RuntimeError carrying the stderr payload."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            return_value=_completed(
                returncode=1,
                stdout="",
                stderr=_CONNECT_FAILURE_STDERR,
            ),
        ),
    ):
        with pytest.raises(RuntimeError, match="drozer console connect failed"):
            await _call_scan(str(apk), package_name="com.example.target")


async def test_non_connection_nonzero_exit_also_raises(tmp_path: Path) -> None:
    """A non-zero exit that is NOT a connection error still raises rather
    than silently returning a partial result."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            return_value=_completed(
                returncode=2,
                stdout="",
                stderr="some other failure",
            ),
        ),
    ):
        with pytest.raises(RuntimeError, match="exited 2"):
            await _call_scan(str(apk), package_name="com.example.target")


async def test_subprocess_timeout_becomes_runtime_error(tmp_path: Path) -> None:
    """`subprocess.TimeoutExpired` is caught and rethrown as RuntimeError
    so the caller never sees a bare `TimeoutExpired` leaking up."""
    apk = _make_apk(tmp_path)
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="drozer", timeout=180),
        ),
    ):
        with pytest.raises(RuntimeError, match="drozer timed out after"):
            await _call_scan(str(apk), package_name="com.example.target")


# ---------------------------------------------------------------------------
# Package-name resolution
# ---------------------------------------------------------------------------


async def test_missing_apk_without_package_override_raises(
    tmp_path: Path,
) -> None:
    """When no `package_name=` override is supplied and the APK does not
    exist, the FileNotFoundError from `_extract_package_from_apk` reaches
    the caller untouched."""
    nonexistent = tmp_path / "nope.apk"
    with patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"):
        with pytest.raises(FileNotFoundError, match="apk not found"):
            await _call_scan(str(nonexistent), package_name=None)


async def test_package_override_skips_apk_extraction(tmp_path: Path) -> None:
    """A `package_name=` override is taken at face value — even when the
    apk_path points at a non-APK file. This lets a VR persona target a
    package that is already on the device without staging the APK
    locally."""
    not_an_apk = tmp_path / "not-an-apk.bin"
    not_an_apk.write_bytes(b"junk")
    with (
        patch("android_mcp.tools.drozer.shutil.which", return_value="/fake/drozer"),
        patch(
            "android_mcp.tools.drozer.subprocess.run",
            side_effect=_by_call_args(
                _ATTACKSURFACE_NOT_DEBUGGABLE,
                _PROVIDER_INJECTION_CLEAN,
                _BROWSABLE_EMPTY,
            ),
        ),
    ):
        result = await _call_scan(
            str(not_an_apk), package_name="com.override.example",
        )

    assert result["package"] == "com.override.example"


# ---------------------------------------------------------------------------
# Direct parser exercises — independent of subprocess plumbing
# ---------------------------------------------------------------------------


def test_parse_attacksurface_blank_input() -> None:
    """All zero counts and `is_debuggable=False` for an empty input —
    failing gracefully matters more here than raising."""
    from android_mcp.tools.drozer import _parse_attacksurface

    assert _parse_attacksurface("") == {
        "activities": 0,
        "receivers": 0,
        "providers": 0,
        "services": 0,
        "is_debuggable": False,
    }


def test_parse_provider_injection_ignores_unknown_sections() -> None:
    """Unknown section headers (future drozer additions) don't crash the
    parser — findings outside the known vector sections are skipped."""
    from android_mcp.tools.drozer import _parse_provider_injection

    blob = (
        "Some Future Section:\n"
        "  content://com.example.target/x\n"
        "Injection in Projection:\n"
        "  content://com.example.target/y\n"
    )
    findings = _parse_provider_injection(blob)
    assert findings == [
        {"uri": "content://com.example.target/y", "vector": "projection"},
    ]


def test_parse_activity_browsable_handles_two_blocks() -> None:
    """Two `Package:` headers yield two separate entries — useful for the
    rare third-party drozer forks that scan multi-package apps in one
    call."""
    from android_mcp.tools.drozer import _parse_activity_browsable

    blob = (
        "Package: a.b.c\n"
        "  Invocable URIs:\n"
        "    one://x\n"
        "Package: d.e.f\n"
        "  Invocable URIs:\n"
        "    two://y\n"
        "  Classes:\n"
        "    d.e.f.Foo\n"
    )
    result = _parse_activity_browsable(blob)
    assert result == [
        {"package": "a.b.c", "invocable_uris": ["one://x"], "classes": []},
        {
            "package": "d.e.f",
            "invocable_uris": ["two://y"],
            "classes": ["d.e.f.Foo"],
        },
    ]


# ---------------------------------------------------------------------------
# Smoke test against the real drozer binary
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("drozer") is None,
    reason="drozer not on PATH; skipping live smoke test",
)
async def test_real_drozer_unreachable_agent_raises(tmp_path: Path) -> None:
    """If the real `drozer` binary is installed but no agent is reachable,
    the wrapper surfaces a RuntimeError rather than hanging or returning
    a malformed payload. We do not assert specific stderr text — the
    important thing is the envelope."""
    apk = _make_apk(tmp_path)
    with pytest.raises(RuntimeError):
        # Use a package name guaranteed not to be installed; the agent
        # connection itself will fail before that even matters.
        await _call_scan(
            str(apk),
            package_name="com.android_mcp.drozer.smoketest.nonexistent",
        )
