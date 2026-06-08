"""Tests for the qark wrapper — Quick Android Review Kit static rules.

These tests run without ``qark`` installed: ``subprocess.run`` is patched
at the module level so the wrapper exercises every parse path against
canned JSON payloads. The mock-based suite is the load-bearing one —
it covers the IssueEncoder shape, the empty-result path, the broken-
JSON envelope, and both the ``--apk`` / ``--java`` invocation variants
without needing the real LinkedIn qark package on PATH.

One smoke-test exercises the real binary when it is on PATH, otherwise
it skips cleanly. That keeps CI green when qark is missing while still
catching upstream behavior drift if the operator's environment has it
installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _make_apk(tmp_path: Path) -> Path:
    """Place a zip-magic stub at .apk path. Content is irrelevant —
    the subprocess call is mocked; only the path-resolution branch
    of the handler touches this file."""
    apk = tmp_path / "stub.apk"
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


async def _call_scan(
    apk_path: str,
    decompiled_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve the registered ``qark_scan`` handler and call it."""
    from android_mcp.tools.qark import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture qark_scan"
    return await fn(apk_path=apk_path, decompiled_dir=decompiled_dir)


def _write_report(report_dir: Path, payload: Any) -> None:
    """Drop a ``report.json`` into ``report_dir`` containing ``payload``."""
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


def _run_writing_report(
    payload: Any,
    *,
    returncode: int = 0,
    stderr: str = "",
) -> Any:
    """Build a ``subprocess.run`` stand-in that writes a qark report
    side-effectfully and then returns a CompletedProcess stub.

    QARK's CLI dumps its report into ``--report-path``; emulate that
    by capturing the path off the argv and writing the JSON there.
    """

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        # Find the --report-path argument; QARK always pairs it with
        # an explicit value so we walk pairs.
        report_path: str | None = None
        for i, tok in enumerate(cmd):
            if tok == "--report-path" and i + 1 < len(cmd):
                report_path = cmd[i + 1]
                break
        assert report_path is not None, "wrapper must pass --report-path"
        _write_report(Path(report_path), payload)
        return _completed(returncode=returncode, stderr=stderr)

    return _side_effect


# ---------------------------------------------------------------------------
# Canned QARK payloads. Mirrors what ``IssueEncoder`` produces under
# json_report.jinja: a top-level list of issue dicts. The Enum-name
# serialisation is the documented shape ("WARNING" / "VULNERABILITY"
# rather than the Severity object itself).
# ---------------------------------------------------------------------------


_TYPICAL_ISSUES = [
    {
        "category": "manifest",
        "name": "ExportedAndroidArtifactsCheck",
        "severity": "VULNERABILITY",
        "description": "Activity com.example.Main is exported without permission",
        "line_number": [12, 18],
        "file_object": "/decoded/AndroidManifest.xml",
        "apk_exploit_dict": None,
    },
    {
        "category": "webview",
        "name": "WebViewAddJavascriptInterfaceCheck",
        "severity": "WARNING",
        "description": "addJavascriptInterface usage without @JavascriptInterface guard",
        "line_number": [42, 42],
        "file_object": "/decoded/com/example/MyView.java",
        "apk_exploit_dict": {"target_sdk": 17},
    },
    {
        "category": "crypto",
        "name": "WeakHashCheck",
        "severity": "INFO",
        "description": "MD5 hash used; consider SHA-256",
        "line_number": None,
        "file_object": "/decoded/com/example/Util.java",
        "apk_exploit_dict": None,
    },
]


# ---------------------------------------------------------------------------
# Install-hint envelope
# ---------------------------------------------------------------------------


async def test_missing_qark_raises_runtime_error(tmp_path: Path) -> None:
    """``qark`` not on PATH → RuntimeError carrying the install hint."""
    apk = _make_apk(tmp_path)
    with patch("android_mcp.tools.qark.shutil.which", return_value=None):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_scan(str(apk))
    msg = str(exc_info.value)
    assert "qark not on PATH" in msg
    assert "pip install qark" in msg


# ---------------------------------------------------------------------------
# Happy path — every parse branch exercised end-to-end
# ---------------------------------------------------------------------------


async def test_full_shape_returned(tmp_path: Path) -> None:
    """End-to-end happy path returns the documented five-key shape per row."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_run_writing_report(_TYPICAL_ISSUES),
        ),
    ):
        result = await _call_scan(str(apk))

    assert isinstance(result, list)
    assert len(result) == 3
    expected_keys = {"rule_id", "severity", "file", "line", "snippet"}
    for row in result:
        assert set(row.keys()) == expected_keys

    first = result[0]
    assert first["rule_id"] == "ExportedAndroidArtifactsCheck"
    assert first["severity"] == "VULNERABILITY"
    assert first["file"] == "/decoded/AndroidManifest.xml"
    assert first["line"] == 12  # first element of [12, 18]
    assert "exported without permission" in first["snippet"]


async def test_line_number_none_passes_through(tmp_path: Path) -> None:
    """Issues without a ``line_number`` surface as ``line=None`` rather
    than raising — qark plugins routinely omit line spans for whole-file
    or manifest-level findings."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_run_writing_report(_TYPICAL_ISSUES),
        ),
    ):
        result = await _call_scan(str(apk))

    weak_hash = next(r for r in result if r["rule_id"] == "WeakHashCheck")
    assert weak_hash["line"] is None


async def test_empty_report_returns_empty_list(tmp_path: Path) -> None:
    """A clean APK yields an empty JSON array → empty list response.
    No exception, no synthesized "all good" row."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_run_writing_report([]),
        ),
    ):
        result = await _call_scan(str(apk))

    assert result == []


async def test_blank_report_returns_empty_list(tmp_path: Path) -> None:
    """A whitespace-only ``report.json`` (rare qark edge case) is
    treated as empty rather than raising."""
    apk = _make_apk(tmp_path)

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        report_path = cmd[cmd.index("--report-path") + 1]
        Path(report_path).mkdir(parents=True, exist_ok=True)
        (Path(report_path) / "report.json").write_text("   \n", encoding="utf-8")
        return _completed()

    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_side_effect,
        ),
    ):
        result = await _call_scan(str(apk))

    assert result == []


# ---------------------------------------------------------------------------
# Tolerance for qark version drift
# ---------------------------------------------------------------------------


async def test_dict_wrapped_issues_tolerated(tmp_path: Path) -> None:
    """An older qark release that wraps the list under ``{"issues": [...]}``
    is parsed the same as the flat-list layout."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_run_writing_report({"issues": _TYPICAL_ISSUES}),
        ),
    ):
        result = await _call_scan(str(apk))

    assert len(result) == 3


async def test_missing_fields_get_defaults(tmp_path: Path) -> None:
    """An issue with only ``name`` set surfaces with empty string
    defaults rather than ``None`` on file/snippet."""
    apk = _make_apk(tmp_path)
    payload = [{"name": "MinimalRule"}]
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_run_writing_report(payload),
        ),
    ):
        result = await _call_scan(str(apk))

    assert result == [
        {
            "rule_id": "MinimalRule",
            "severity": "WARNING",  # default when missing
            "file": "",
            "line": None,
            "snippet": "",
        },
    ]


async def test_non_dict_entries_skipped(tmp_path: Path) -> None:
    """Stray non-dict items in the array don't crash the parser — they
    are dropped silently. This guards against future qark format drift
    that mixes header dicts and string footers in the array."""
    apk = _make_apk(tmp_path)
    payload = [
        "not-a-dict",
        42,
        {"name": "RealRule", "severity": "ERROR"},
        None,
    ]
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_run_writing_report(payload),
        ),
    ):
        result = await _call_scan(str(apk))

    assert len(result) == 1
    assert result[0]["rule_id"] == "RealRule"
    assert result[0]["severity"] == "ERROR"


# ---------------------------------------------------------------------------
# CLI argv routing: --apk vs --java
# ---------------------------------------------------------------------------


async def test_apk_mode_when_decompiled_dir_omitted(tmp_path: Path) -> None:
    """No ``decompiled_dir`` → wrapper invokes ``qark --apk <path>``."""
    apk = _make_apk(tmp_path)
    captured_cmd: list[list[str]] = []

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        captured_cmd.append(list(cmd))
        report_path = cmd[cmd.index("--report-path") + 1]
        _write_report(Path(report_path), [])
        return _completed()

    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_side_effect,
        ),
    ):
        await _call_scan(str(apk))

    assert len(captured_cmd) == 1
    cmd = captured_cmd[0]
    assert "--apk" in cmd
    assert str(apk) in cmd
    assert "--java" not in cmd


async def test_java_mode_when_decompiled_dir_supplied(tmp_path: Path) -> None:
    """``decompiled_dir`` set → wrapper invokes ``qark --java <dir>``
    instead of ``--apk``, skipping QARK's internal decompile step."""
    apk = _make_apk(tmp_path)
    decompiled = tmp_path / "jadx-out" / "sources"
    decompiled.mkdir(parents=True)
    captured_cmd: list[list[str]] = []

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        captured_cmd.append(list(cmd))
        report_path = cmd[cmd.index("--report-path") + 1]
        _write_report(Path(report_path), [])
        return _completed()

    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_side_effect,
        ),
    ):
        await _call_scan(str(apk), decompiled_dir=str(decompiled))

    assert len(captured_cmd) == 1
    cmd = captured_cmd[0]
    assert "--java" in cmd
    assert str(decompiled) in cmd
    assert "--apk" not in cmd


async def test_report_type_always_json(tmp_path: Path) -> None:
    """Wrapper hard-codes ``--report-type json`` so the parser shape
    stays predictable regardless of qark default-config drift."""
    apk = _make_apk(tmp_path)
    captured_cmd: list[list[str]] = []

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        captured_cmd.append(list(cmd))
        report_path = cmd[cmd.index("--report-path") + 1]
        _write_report(Path(report_path), [])
        return _completed()

    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_side_effect,
        ),
    ):
        await _call_scan(str(apk))

    cmd = captured_cmd[0]
    assert "--report-type" in cmd
    assert cmd[cmd.index("--report-type") + 1] == "json"


# ---------------------------------------------------------------------------
# Failure envelopes
# ---------------------------------------------------------------------------


async def test_missing_apk_raises_file_not_found(tmp_path: Path) -> None:
    """A bogus apk_path raises ``FileNotFoundError`` before any
    subprocess work happens — the wrapper validates inputs eagerly."""
    nonexistent = tmp_path / "does_not_exist.apk"
    with patch("android_mcp.tools.qark.shutil.which", return_value="/fake/qark"):
        with pytest.raises(FileNotFoundError):
            await _call_scan(str(nonexistent))


async def test_missing_decompiled_dir_raises_file_not_found(
    tmp_path: Path,
) -> None:
    """A bogus ``decompiled_dir`` also raises ``FileNotFoundError`` up
    front, with a distinct error message naming the directory."""
    apk = _make_apk(tmp_path)
    nonexistent = tmp_path / "no-such-dir"
    with patch("android_mcp.tools.qark.shutil.which", return_value="/fake/qark"):
        with pytest.raises(FileNotFoundError) as exc_info:
            await _call_scan(str(apk), decompiled_dir=str(nonexistent))
    assert "decompiled_dir" in str(exc_info.value)


async def test_subprocess_timeout_becomes_runtime_error(tmp_path: Path) -> None:
    """``subprocess.TimeoutExpired`` is caught and rethrown as
    ``RuntimeError`` carrying the wall-clock cap. Without this envelope
    the caller sees an awkward subprocess-internal exception."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="qark", timeout=600),
        ),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            await _call_scan(str(apk))


async def test_nonzero_exit_raises_runtime_error(tmp_path: Path) -> None:
    """A non-zero exit from qark surfaces stderr in the RuntimeError
    message rather than being silently treated as zero findings."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            return_value=_completed(
                returncode=2,
                stderr="ERROR: could not parse manifest",
            ),
        ),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_scan(str(apk))
    assert "qark exited 2" in str(exc_info.value)
    assert "could not parse manifest" in str(exc_info.value)


async def test_missing_report_raises_runtime_error(tmp_path: Path) -> None:
    """A zero-exit qark run that nonetheless produces no ``report.json``
    raises ``RuntimeError`` — silent empty payloads would mask broken
    configurations far worse than a loud failure."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            return_value=_completed(stdout="finished without writing"),
        ),
    ):
        with pytest.raises(RuntimeError, match="did not produce"):
            await _call_scan(str(apk))


async def test_invalid_json_raises_runtime_error(tmp_path: Path) -> None:
    """A garbled report file (qark crashed mid-write, disk full, etc.)
    raises ``RuntimeError`` rather than swallowing a JSONDecodeError."""
    apk = _make_apk(tmp_path)

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        report_path = cmd[cmd.index("--report-path") + 1]
        Path(report_path).mkdir(parents=True, exist_ok=True)
        (Path(report_path) / "report.json").write_text(
            "{not valid json",
            encoding="utf-8",
        )
        return _completed()

    with (
        patch(
            "android_mcp.tools.qark.shutil.which",
            return_value="/fake/qark",
        ),
        patch(
            "android_mcp.tools.qark.subprocess.run",
            side_effect=_side_effect,
        ),
    ):
        with pytest.raises(RuntimeError, match="not valid JSON"):
            await _call_scan(str(apk))


# ---------------------------------------------------------------------------
# Direct parser exercises — independent of subprocess plumbing
# ---------------------------------------------------------------------------


def test_parse_handles_enum_dict_severity() -> None:
    """Defensive: an older IssueEncoder release that serialises the
    Severity enum as ``{"name": "WARNING", "value": 1}`` is also
    handled by pulling ``.name`` out."""
    from android_mcp.tools.qark import _parse_qark_report

    raw = json.dumps(
        [{
            "name": "EdgeCaseRule",
            "severity": {"name": "ERROR", "value": 2},
            "file_object": "/x.java",
            "line_number": [3, 4],
            "description": "edge",
        }],
    )
    result = _parse_qark_report(raw)
    assert result == [{
        "rule_id": "EdgeCaseRule",
        "severity": "ERROR",
        "file": "/x.java",
        "line": 3,
        "snippet": "edge",
    }]


def test_parse_handles_integer_line_number() -> None:
    """When ``line_number`` is a single int (rare plugin variant),
    we use it directly rather than dropping to ``None``."""
    from android_mcp.tools.qark import _parse_qark_report

    raw = json.dumps(
        [{"name": "R", "severity": "INFO", "line_number": 7}],
    )
    result = _parse_qark_report(raw)
    assert result[0]["line"] == 7


def test_parse_unexpected_top_level_type_raises() -> None:
    """A top-level scalar payload (definitely not a qark report) raises
    rather than silently returning empty."""
    from android_mcp.tools.qark import _parse_qark_report

    with pytest.raises(RuntimeError, match="unexpected top-level type"):
        _parse_qark_report(json.dumps("just a string"))


# ---------------------------------------------------------------------------
# Smoke test against the real qark binary
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("qark") is None,
    reason="real qark binary not on PATH",
)
async def test_real_qark_missing_apk_raises(tmp_path: Path) -> None:
    """When the real ``qark`` binary is installed, pointing it at a
    nonexistent APK raises ``FileNotFoundError`` before subprocess
    invocation (input validation runs first)."""
    nonexistent = tmp_path / "no-such.apk"
    with pytest.raises(FileNotFoundError):
        await _call_scan(str(nonexistent))
