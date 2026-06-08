"""Tests for the AndroBugs Framework wrapper.

The default suite runs without an AndroBugs checkout: ``subprocess.run`` is
patched at the module level so the wrapper exercises every parse branch
against canned report payloads, and ``ANDROBUGS_HOME`` is faked via
``monkeypatch`` plus on-disk script stubs. The mock-based path is the
load-bearing one — it covers level routing (Critical/Warning/Notice →
vulnerabilities, Info → info), Vector ID extraction, CVE tag extraction,
empty-tag handling, title-vs-details indent split, and the install-hint
envelope for the missing-``ANDROBUGS_HOME`` case.

A single smoke test runs against the real AndroBugs checkout when
``ANDROBUGS_HOME`` is set, otherwise it skips cleanly. That keeps the suite
green on a fresh dev box while still catching upstream behavior drift if
the operator has the framework installed.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _make_apk(tmp_path: Path) -> Path:
    """Place a zip-magic stub at ``.apk`` path. Content is irrelevant —
    the subprocess call is mocked; only the path-resolution branch of
    the handler touches this file."""
    apk = tmp_path / "stub.apk"
    apk.write_bytes(b"PK\x03\x04")
    return apk


def _make_home_with_script(tmp_path: Path, script_name: str = "androbugs.py") -> Path:
    """Create a fake ANDROBUGS_HOME with ``script_name`` inside it.

    Returns the home directory path. Caller wires it onto the env via
    ``monkeypatch.setenv``.
    """
    home = tmp_path / "androbugs-home"
    home.mkdir()
    (home / script_name).write_text("#!/usr/bin/env python\n", encoding="utf-8")
    return home


def _make_home_with_exe(tmp_path: Path) -> Path:
    """Create a fake ANDROBUGS_HOME with an executable-stamped exe inside."""
    home = tmp_path / "androbugs-home"
    home.mkdir()
    exe = home / "androbugs.exe"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return home


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
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Resolve the registered ``androbugs_scan`` handler and call it."""
    from android_mcp.tools.androbugs import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture androbugs_scan"
    return await fn(apk_path=apk_path, output_dir=output_dir)


def _write_report(report_dir: Path, content: str, name: str = "com.example_sig.txt") -> Path:
    """Drop a report file into ``report_dir`` containing ``content``."""
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def _run_writing_report(
    content: str,
    *,
    returncode: int = 0,
    stderr: str = "",
    name: str = "com.example_sig.txt",
) -> Any:
    """Build a ``subprocess.run`` stand-in that writes a report
    side-effectfully and then returns a CompletedProcess stub.

    AndroBugs writes its report into the ``-o`` directory; emulate that
    by capturing the path off argv and dropping the canned content
    there. Mirrors the qark test helper.
    """

    def _side_effect(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        report_dir: str | None = None
        for i, tok in enumerate(cmd):
            if tok == "-o" and i + 1 < len(cmd):
                report_dir = cmd[i + 1]
                break
        assert report_dir is not None, "wrapper must pass -o to AndroBugs"
        _write_report(Path(report_dir), content, name=name)
        return _completed(returncode=returncode, stderr=stderr)

    return _side_effect


# ---------------------------------------------------------------------------
# Canned AndroBugs reports — pruned to the structural shape the parser keys
# on, not full-fidelity copies of real outputs.
# ---------------------------------------------------------------------------


_TYPICAL_REPORT = """\
*************************************************************************
**   AndroBugs Framework - Android App Security Vulnerability Scanner  **
*************************************************************************
Platform: Android
Package Name: com.vodafone.selfservis
Package Version Name: 12.3.4
Package Version Code: 1234
Min Sdk: 21
Target Sdk: 31
MD5   : abcdef
SHA1  : abcdef
SHA256: abcdef
SHA512: abcdef
Analyze Signature: f00ba1
------------------------------------------------------------
[Critical] <WebView><#CVE-2013-4710#> WebView Remote Code Execution Vulnerability (Vector ID: WEBVIEW_RCE):
           addJavascriptInterface() usage without @JavascriptInterface guard
           on a target SDK < 17 is a remote code execution primitive.
               => Lcom/vodafone/selfservis/MyView;->onCreate(...)V
               => Lcom/vodafone/selfservis/OtherView;->setup()V
[Warning] <SSL_Security> SSL Certificate Verification Checking (Vector ID: SSL_X509):
           X509TrustManager override accepts every certificate. MITM is feasible.
               => Lcom/vodafone/selfservis/net/InsecureTrustManager;
[Notice] <Database> File Unsafe Delete Checking (Vector ID: FILE_DELETE):
           file.delete() does not actually zero the contents; recovery is trivial.
               => Lcom/vodafone/selfservis/cache/CacheCleaner;->purge()V
[Info] <SSL_Security> Did not detect insecure HTTP URLs in the bytecode. (Vector ID: SSL_URLS_NOT_IN_HTTPS):
           All discovered URLs use HTTPS.
[Info]  Did not detect this app is getting the device id by TelephonyManager.getDeviceId(). (Vector ID: SENSITIVE_DEVICE_ID):
           OK — IMEI fingerprinting absent.
------------------------------------------------------------
AndroBugs analyzing time: 12.34 secs
Total elapsed time: 14.56 secs
"""


_REPORT_NO_VECTOR_IDS = """\
Platform: Android
Package Name: com.example.app
------------------------------------------------------------
[Critical] <Debug> Android Debug Mode Checking:
           DEBUG mode is ON in AndroidManifest.xml.
[Info]  Did not detect codes for sending SMS messages.:
           Clean.
------------------------------------------------------------
AndroBugs analyzing time: 1.00 secs
"""


_REPORT_EMPTY_FINDINGS = """\
Platform: Android
Package Name: com.empty.app
------------------------------------------------------------
------------------------------------------------------------
AndroBugs analyzing time: 0.50 secs
"""


# ---------------------------------------------------------------------------
# ANDROBUGS_HOME envelope
# ---------------------------------------------------------------------------


async def test_missing_home_env_raises_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ANDROBUGS_HOME`` unset → RuntimeError carrying the install hint."""
    monkeypatch.delenv("ANDROBUGS_HOME", raising=False)
    apk = _make_apk(tmp_path)
    with pytest.raises(RuntimeError) as exc_info:
        await _call_scan(str(apk))
    msg = str(exc_info.value)
    assert "ANDROBUGS_HOME" in msg
    assert "AndroBugs Framework" in msg


async def test_empty_home_env_raises_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ANDROBUGS_HOME=`` (empty string) is treated as unset, not as PWD."""
    monkeypatch.setenv("ANDROBUGS_HOME", "")
    apk = _make_apk(tmp_path)
    with pytest.raises(RuntimeError) as exc_info:
        await _call_scan(str(apk))
    assert "ANDROBUGS_HOME" in str(exc_info.value)


async def test_home_pointing_at_nonexistent_path_raises_file_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ANDROBUGS_HOME → path that doesn't exist → FileNotFoundError."""
    monkeypatch.setenv("ANDROBUGS_HOME", str(tmp_path / "no-such"))
    apk = _make_apk(tmp_path)
    with pytest.raises(FileNotFoundError) as exc_info:
        await _call_scan(str(apk))
    assert "ANDROBUGS_HOME" in str(exc_info.value)


async def test_home_without_entrypoint_raises_file_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ANDROBUGS_HOME exists but contains no androbugs.py/.exe → FileNotFoundError."""
    home = tmp_path / "androbugs-home"
    home.mkdir()
    # Drop an unrelated file so the directory isn't empty
    (home / "README.md").write_text("not a script", encoding="utf-8")
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with pytest.raises(FileNotFoundError) as exc_info:
        await _call_scan(str(apk))
    msg = str(exc_info.value)
    assert "AndroBugs entrypoint not found" in msg


async def test_home_with_camelcase_script_resolves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The PRD-mentioned ``AndroBugs.py`` (uppercase) variant also resolves."""
    home = _make_home_with_script(tmp_path, script_name="AndroBugs.py")
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk))
    assert result["package_name"] == "com.vodafone.selfservis"


async def test_home_with_exe_uses_direct_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``androbugs.exe`` is present, the wrapper invokes it directly
    without prepending ``python`` (the Windows standalone bundles its
    own Python 2.7 runtime)."""
    home = _make_home_with_exe(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    seen: dict[str, Any] = {}
    side_effect = _run_writing_report(_TYPICAL_REPORT)

    def _capture(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = cmd
        return side_effect(cmd, *args, **kwargs)

    with patch("android_mcp.tools.androbugs.subprocess.run", side_effect=_capture):
        await _call_scan(str(apk))
    cmd = seen["cmd"]
    assert cmd[0].endswith("androbugs.exe")
    # python invocation must NOT have been prepended
    assert not any(tok.endswith("python") or tok.endswith("python2") for tok in cmd)


# ---------------------------------------------------------------------------
# Happy path — every parse branch exercised end-to-end
# ---------------------------------------------------------------------------


async def test_typical_report_routes_severities_correctly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Critical/Warning/Notice → vulnerabilities; Info → info."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk))

    assert result["package_name"] == "com.vodafone.selfservis"
    assert len(result["vulnerabilities"]) == 3
    assert len(result["info"]) == 2
    levels = [v["level"] for v in result["vulnerabilities"]]
    assert "Critical" in levels
    assert "Warning" in levels
    assert "Notice" in levels
    for entry in result["info"]:
        assert entry["level"] == "Info"


async def test_finding_fields_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each finding carries vector_id, level, summary, tags, cve, title, details."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk))

    webview = next(v for v in result["vulnerabilities"] if v["vector_id"] == "WEBVIEW_RCE")
    assert webview["level"] == "Critical"
    assert webview["cve"] == "CVE-2013-4710"
    assert webview["tags"] == ["WebView"]
    assert "Remote Code Execution" in webview["summary"]
    assert "addJavascriptInterface" in webview["title"]
    assert "Lcom/vodafone/selfservis/MyView" in webview["details"]
    assert "OtherView" in webview["details"]


async def test_finding_without_cve_has_cve_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rules without a ``<#CVE-...#>`` block surface ``cve: None``."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk))

    ssl_finding = next(v for v in result["vulnerabilities"] if v["vector_id"] == "SSL_X509")
    assert ssl_finding["cve"] is None
    assert ssl_finding["tags"] == ["SSL_Security"]


async def test_finding_with_empty_tag_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rules with no ``<tag>`` block surface with empty tags list."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk))

    no_tag = next(
        v for v in result["info"] if v["vector_id"] == "SENSITIVE_DEVICE_ID"
    )
    assert no_tag["tags"] == []
    assert no_tag["cve"] is None


async def test_report_without_vector_ids_parses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``-v`` was not passed (operator reused an external report),
    Vector IDs are absent; the parser keeps the finding but leaves
    ``vector_id`` empty rather than dropping the row."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_REPORT_NO_VECTOR_IDS),
    ):
        result = await _call_scan(str(apk))

    assert len(result["vulnerabilities"]) == 1
    assert len(result["info"]) == 1
    assert result["vulnerabilities"][0]["vector_id"] == ""
    assert result["vulnerabilities"][0]["level"] == "Critical"
    assert result["vulnerabilities"][0]["tags"] == ["Debug"]


async def test_empty_findings_report_returns_empty_lists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A report with only header + trailer (no findings) returns empty lists."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_REPORT_EMPTY_FINDINGS),
    ):
        result = await _call_scan(str(apk))

    assert result["vulnerabilities"] == []
    assert result["info"] == []
    assert result["package_name"] == "com.empty.app"


# ---------------------------------------------------------------------------
# CLI argv shape — confirm what we pass to AndroBugs
# ---------------------------------------------------------------------------


async def test_cli_passes_required_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wrapper must pass ``-f <apk>``, ``-o <dir>``, and ``-v``."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    seen: dict[str, Any] = {}
    side_effect = _run_writing_report(_TYPICAL_REPORT)

    def _capture(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        seen["cmd"] = cmd
        return side_effect(cmd, *args, **kwargs)

    with patch("android_mcp.tools.androbugs.subprocess.run", side_effect=_capture):
        await _call_scan(str(apk))

    cmd = seen["cmd"]
    assert "-f" in cmd
    assert cmd[cmd.index("-f") + 1] == str(apk)
    assert "-o" in cmd
    assert "-v" in cmd  # Vector IDs are load-bearing for the parser


# ---------------------------------------------------------------------------
# output_dir lifecycle
# ---------------------------------------------------------------------------


async def test_output_dir_none_does_not_leak_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``output_dir=None`` uses a tempdir; ``report_path`` is None (the
    file has been removed by the time the caller sees the result)."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk), output_dir=None)
    assert result["report_path"] is None


async def test_output_dir_supplied_returns_report_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``output_dir`` preserves the file and returns its path."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    out = tmp_path / "reports"
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        result = await _call_scan(str(apk), output_dir=str(out))
    assert result["report_path"] is not None
    assert Path(result["report_path"]).exists()
    assert Path(result["report_path"]).parent == out.resolve()


async def test_output_dir_created_when_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested ``output_dir`` paths that don't exist are created (mkdir -p)."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    out = tmp_path / "a" / "b" / "c"
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT),
    ):
        await _call_scan(str(apk), output_dir=str(out))
    assert out.is_dir()


# ---------------------------------------------------------------------------
# Failure envelopes
# ---------------------------------------------------------------------------


async def test_missing_apk_raises_file_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bogus apk_path raises FileNotFoundError before subprocess invocation."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    nonexistent = tmp_path / "no-such.apk"
    with pytest.raises(FileNotFoundError):
        await _call_scan(str(nonexistent))


async def test_apk_path_pointing_at_directory_raises_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory passed as ``apk_path`` raises ValueError, not FileNotFoundError."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    a_dir = tmp_path / "subdir"
    a_dir.mkdir()
    with pytest.raises(ValueError):
        await _call_scan(str(a_dir))


async def test_subprocess_timeout_becomes_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``subprocess.TimeoutExpired`` surfaces as RuntimeError naming the timeout."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)

    def _raise_timeout(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=["androbugs"], timeout=300)

    with patch("android_mcp.tools.androbugs.subprocess.run", side_effect=_raise_timeout):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_scan(str(apk))
    assert "timed out" in str(exc_info.value)


async def test_nonzero_exit_raises_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-zero exit surfaces stderr in the RuntimeError envelope."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        return_value=_completed(returncode=2, stderr="manifest read error"),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_scan(str(apk))
    msg = str(exc_info.value)
    assert "exited 2" in msg
    assert "manifest read error" in msg


async def test_no_report_file_produced_raises_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero-exit AndroBugs run that nonetheless produced no .txt file → RuntimeError."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        return_value=_completed(returncode=0, stdout="(no output)"),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await _call_scan(str(apk))
    assert "did not produce" in str(exc_info.value)


async def test_newest_report_file_picked_when_multiple_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the output dir has older ``.txt`` files from prior runs, the
    most recently modified one is picked (AndroBugs always writes a
    fresh file per run with a new signature suffix)."""
    home = _make_home_with_script(tmp_path)
    monkeypatch.setenv("ANDROBUGS_HOME", str(home))
    apk = _make_apk(tmp_path)
    out = tmp_path / "reports"
    out.mkdir()
    old = out / "com.example_old.txt"
    old.write_text("stale", encoding="utf-8")
    # Backdate the stale file so the parser does not pick it.
    old_mtime = old.stat().st_mtime - 3600
    os.utime(old, (old_mtime, old_mtime))

    with patch(
        "android_mcp.tools.androbugs.subprocess.run",
        side_effect=_run_writing_report(_TYPICAL_REPORT, name="com.example_new.txt"),
    ):
        result = await _call_scan(str(apk), output_dir=str(out))
    assert Path(result["report_path"]).name == "com.example_new.txt"


# ---------------------------------------------------------------------------
# Direct parser exercises — independent of subprocess plumbing
# ---------------------------------------------------------------------------


def test_parse_extracts_package_name() -> None:
    """``Package Name:`` header line surfaces as ``package_name``."""
    from android_mcp.tools.androbugs import _parse_androbugs_report

    out = _parse_androbugs_report(_TYPICAL_REPORT)
    assert out["package_name"] == "com.vodafone.selfservis"


def test_parse_returns_none_package_for_report_without_header() -> None:
    """Report with no ``Package Name:`` line returns ``package_name: None``."""
    from android_mcp.tools.androbugs import _parse_androbugs_report

    headerless = "[Info] Did not detect things. (Vector ID: NOTHING):\n           Clean.\n"
    out = _parse_androbugs_report(headerless)
    assert out["package_name"] is None
    assert len(out["info"]) == 1


def test_parse_splits_title_from_details_by_indent() -> None:
    """11-space indent → title; 15+-space indent → details.

    AndroBugs's TextWrapper uses these two indent widths to render the
    description vs the call-site list; the parser undoes the column
    formatting and emits content in two separate fields.
    """
    from android_mcp.tools.androbugs import _parse_androbugs_report

    out = _parse_androbugs_report(_TYPICAL_REPORT)
    webview = next(v for v in out["vulnerabilities"] if v["vector_id"] == "WEBVIEW_RCE")
    # title block (11-space indent in the source)
    assert "addJavascriptInterface" in webview["title"]
    assert "Lcom/vodafone" not in webview["title"]
    # details block (15-space indent)
    assert "Lcom/vodafone/selfservis/MyView" in webview["details"]
    assert "addJavascriptInterface" not in webview["details"]


def test_parse_handles_back_to_back_findings_without_horizontal_rule() -> None:
    """Findings can fire one after another with no divider between them
    — the next header line is itself the boundary."""
    from android_mcp.tools.androbugs import _parse_androbugs_report

    report = (
        "Package Name: com.test.app\n"
        "------------------------------------------------------------\n"
        "[Critical] <A> First finding (Vector ID: FIRST):\n"
        "           First title line.\n"
        "[Warning] <B> Second finding (Vector ID: SECOND):\n"
        "           Second title line.\n"
        "[Info] <C> Third finding (Vector ID: THIRD):\n"
        "           Third title line.\n"
        "------------------------------------------------------------\n"
        "AndroBugs analyzing time: 0.10 secs\n"
    )
    out = _parse_androbugs_report(report)
    assert len(out["vulnerabilities"]) == 2
    assert len(out["info"]) == 1
    assert [v["vector_id"] for v in out["vulnerabilities"]] == ["FIRST", "SECOND"]
    assert out["info"][0]["vector_id"] == "THIRD"


def test_parse_summary_preserves_embedded_parentheses() -> None:
    """A summary that itself contains parentheses (e.g. ``... (Z)V``) is
    not truncated by the optional ``(Vector ID: ...)`` tail matcher."""
    from android_mcp.tools.androbugs import _parse_androbugs_report

    report = (
        "[Notice] <Cmd> Found Runtime.exec(java.lang.String) usage (Vector ID: COMMAND_EXEC):\n"
        "           Description goes here.\n"
    )
    out = _parse_androbugs_report(report)
    finding = out["vulnerabilities"][0]
    assert finding["vector_id"] == "COMMAND_EXEC"
    assert finding["summary"] == "Found Runtime.exec(java.lang.String) usage"


def test_parse_trailer_stops_finding_accumulation() -> None:
    """Trailer lines (``AndroBugs analyzing time:`` etc.) close the
    current finding rather than being absorbed into its body."""
    from android_mcp.tools.androbugs import _parse_androbugs_report

    report = (
        "[Info] <X> Did not detect things. (Vector ID: CLEAN):\n"
        "           Clean.\n"
        "AndroBugs analyzing time: 1.23 secs\n"
        "Total elapsed time: 2.34 secs\n"
    )
    out = _parse_androbugs_report(report)
    info = out["info"][0]
    assert info["title"] == "Clean."
    assert "AndroBugs analyzing time" not in info["title"]
    assert "AndroBugs analyzing time" not in info["details"]


def test_parse_multiple_tags_extracted_in_order() -> None:
    """Two or more ``<tag>`` blocks before the summary are kept as a list,
    preserving emission order."""
    from android_mcp.tools.androbugs import _parse_androbugs_report

    report = (
        "[Warning] <SSL_Security><Network><Hacker> SSL pinning checking (Vector ID: SSL_PIN):\n"
        "           No pinning configured.\n"
    )
    out = _parse_androbugs_report(report)
    finding = out["vulnerabilities"][0]
    assert finding["tags"] == ["SSL_Security", "Network", "Hacker"]
    assert finding["cve"] is None


# ---------------------------------------------------------------------------
# Smoke test against the real AndroBugs checkout
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("ANDROBUGS_HOME"),
    reason="ANDROBUGS_HOME not set — operator has no AndroBugs checkout",
)
async def test_real_androbugs_missing_apk_raises(tmp_path: Path) -> None:
    """With the real AndroBugs checkout configured, pointing the wrapper
    at a nonexistent APK raises FileNotFoundError before subprocess
    invocation (input validation runs first)."""
    nonexistent = tmp_path / "no-such.apk"
    with pytest.raises(FileNotFoundError):
        await _call_scan(str(nonexistent))

