"""qark wrapper — LinkedIn's Quick Android Review Kit static rules.

QARK is a static Android security scanner authored by LinkedIn. It walks
the decompiled Java tree plus the manifest looking for several dozen
classic Android weaknesses: exported components that take intent extras,
WebView misconfigurations, weak crypto, world-readable file modes,
hardcoded secrets, x.509 validation bypasses, and so on. Each rule fires
as an "Issue" with category, name, severity, description, optional line
number, and the file the rule matched in.

The CLI accepts two entry shapes:

- ``qark --apk <path>`` decompiles internally then runs every rule
- ``qark --java <dir>`` skips the decompile step and runs rules against
  an existing Java source tree (useful when the caller already ran
  jadx and wants to avoid the second decompile pass)

QARK only emits its findings to a file (rendered via Jinja from one of
``html``/``xml``/``json``/``csv`` templates); there is no stdout-only
mode. This wrapper forces ``--report-type json``, points QARK at a
fresh temp directory, then reads ``<dir>/report.json`` back and
projects each Issue onto the documented response shape.

OS prerequisite: ``qark`` CLI on PATH. Install via
``pip install qark`` into the operator's Python environment of choice
(QARK targets Python 2.7 / 3.6 historically but the CLI also runs
under 3.12 with minor warnings — pin a virtualenv if it matters).

Acceptance shape per PRD §A-3:
    list of dicts, each with:
        ``rule_id`` (str)     — QARK plugin name (e.g. ``ExportedAndroidArtifactsCheck``)
        ``severity`` (str)    — one of ``"INFO"``/``"WARNING"``/``"ERROR"``/``"VULNERABILITY"``
        ``file`` (str)        — decompiled-source file the rule fired against
        ``line`` (int | None) — first line of the offending range, or ``None``
        ``snippet`` (str)     — QARK's description of the finding
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Wall-clock cap for one full QARK run. QARK's bottleneck is its own
# decompile step (when called with ``--apk``); on a 50 MB customer app
# this can take several minutes because QARK runs procyon/cfr/jdcore in
# sequence. 600s lets the slow tail through without parking the worker
# indefinitely. Callers that already have a jadx tree pass
# ``decompiled_dir`` to skip the duplicate decompile and finish in
# under a minute on typical apps.
_DEFAULT_TIMEOUT_S = 600

_INSTALL_HINT = (
    "qark not on PATH. Install with `pip install qark`; the wrapper "
    "shells out to the `qark` CLI rather than importing the package "
    "directly because qark's library API is not stable across releases. "
    "See https://github.com/linkedin/qark."
)


def register(mcp: Any) -> None:
    @mcp.tool()
    async def qark_scan(
        apk_path: str,
        decompiled_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run QARK's static rule set against an APK or decompiled tree.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.
                Always required — QARK still reads the manifest from
                the APK even when ``decompiled_dir`` is supplied, so
                callers cannot skip the APK reference entirely.
            decompiled_dir: Optional path to an existing jadx-decompiled
                Java tree. When set, QARK runs in ``--java <dir>`` mode
                and skips its own (slow) decompile step. When ``None``,
                QARK is invoked with ``--apk <path>`` and handles
                decompilation internally.

        Returns:
            List of finding dicts in the documented shape. Empty list
            when QARK found nothing. Order matches QARK's own emission
            order.

        Raises:
            FileNotFoundError: ``apk_path`` does not exist, or
                ``decompiled_dir`` was passed but does not resolve.
            RuntimeError: ``qark`` is not on PATH, the subprocess
                timed out, QARK exited non-zero, or the JSON report
                file did not materialise / could not be parsed.
        """
        qark_bin = shutil.which("qark")
        if qark_bin is None:
            raise RuntimeError(_INSTALL_HINT)

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        java_dir: Path | None = None
        if decompiled_dir is not None:
            java_dir = Path(decompiled_dir).expanduser().resolve()
            if not java_dir.exists():
                raise FileNotFoundError(
                    f"decompiled_dir not found: {java_dir}",
                )
            if not java_dir.is_dir():
                raise ValueError(f"not a directory: {java_dir}")

        with tempfile.TemporaryDirectory(prefix="qark-report-") as tmp:
            report_dir = Path(tmp)
            cmd: list[str] = [
                qark_bin,
                "--report-type", "json",
                "--report-path", str(report_dir),
            ]
            if java_dir is not None:
                cmd += ["--java", str(java_dir)]
            else:
                cmd += ["--apk", str(apk)]

            loop = asyncio.get_event_loop()
            try:
                proc = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(  # noqa: S603
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=_DEFAULT_TIMEOUT_S,
                    ),
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"qark timed out after {_DEFAULT_TIMEOUT_S}s on {apk}",
                ) from exc

            if proc.returncode != 0:
                stderr_blob = (proc.stderr or "").strip()
                raise RuntimeError(
                    f"qark exited {proc.returncode}: "
                    f"{stderr_blob or '<no stderr>'}",
                )

            report_path = report_dir / "report.json"
            if not report_path.exists():
                raise RuntimeError(
                    f"qark did not produce {report_path}; stdout was: "
                    f"{(proc.stdout or '').strip() or '<empty>'}",
                )
            try:
                raw = report_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(
                    f"could not read qark report at {report_path}: {exc}",
                ) from exc

            return _parse_qark_report(raw)


def _parse_qark_report(raw: str) -> list[dict[str, Any]]:
    """Project QARK's JSON report onto the documented finding shape.

    QARK's ``json_report.jinja`` template emits the IssueEncoder-serialised
    issue list directly:

        ``[{"category": ..., "name": ..., "severity": ..., "description": ...,
            "line_number": [int, int] | null, "file_object": ...,
            "apk_exploit_dict": {...} | null}, ...]``

    A handful of older qark releases wrap that list in a top-level dict
    keyed under ``"issues"``; both layouts are tolerated. Empty / blank
    payloads return ``[]`` rather than raising.
    """
    stripped = raw.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"qark report is not valid JSON: {exc.msg} at offset {exc.pos}",
        ) from exc

    if isinstance(parsed, dict):
        # Tolerate older qark variants that wrap the list under a key.
        issues = parsed.get("issues") or parsed.get("findings") or []
    elif isinstance(parsed, list):
        issues = parsed
    else:
        raise RuntimeError(
            f"qark report has unexpected top-level type: {type(parsed).__name__}",
        )

    findings: list[dict[str, Any]] = []
    for entry in issues:
        if not isinstance(entry, dict):
            continue
        findings.append(_project_issue(entry))
    return findings


def _project_issue(entry: dict[str, Any]) -> dict[str, Any]:
    """Map one IssueEncoder dict onto the response shape.

    Falls back to defensive defaults rather than raising on missing
    fields; QARK's plugin authors occasionally omit ``line_number`` or
    ``description`` and a single under-specified rule should not blow
    up the whole scan.
    """
    rule_id = entry.get("name") or entry.get("category") or "unknown"
    severity = entry.get("severity")
    if isinstance(severity, dict):
        # Defensive — older IssueEncoder variants serialise the Enum
        # by attribute dict; pull the name out.
        severity = severity.get("name") or "WARNING"
    severity_str = str(severity or "WARNING")

    file_object = entry.get("file_object") or ""
    snippet = entry.get("description") or ""

    line: int | None = None
    raw_line = entry.get("line_number")
    if isinstance(raw_line, (list, tuple)) and raw_line:
        first = raw_line[0]
        if isinstance(first, int):
            line = first
    elif isinstance(raw_line, int):
        line = raw_line

    return {
        "rule_id": str(rule_id),
        "severity": severity_str,
        "file": str(file_object),
        "line": line,
        "snippet": str(snippet),
    }
