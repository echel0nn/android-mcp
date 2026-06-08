"""AndroBugs Framework wrapper — static rules against an APK.

AndroBugs is a Python 2.7 static analyzer authored by Yu-Cheng Lin. It walks
the APK's DEX bytecode plus the manifest looking for a fixed catalogue of
Android-specific weaknesses: exported components, WebView misconfigurations,
weak crypto, master-key (CVE-2013-4787), JavaScript-interface RCE
(CVE-2013-4710), missing SSL pinning, hardcoded URLs without TLS, root
checks, IMEI fingerprinting, and several dozen more vectors. Each rule
fires with one of four severity levels — ``Critical`` / ``Warning`` /
``Notice`` / ``Info`` — and a stable string Vector ID (``WEBVIEW_RCE``,
``SSL_X509``, etc.) that downstream tooling keys on.

Unlike most pip-installable scanners, AndroBugs is shipped as a standalone
git checkout — there is no PyPI release. The operator clones the repo to
some directory and points ``ANDROBUGS_HOME`` at it; this wrapper resolves
the entrypoint at call time. Three layouts are tolerated:

- ``$ANDROBUGS_HOME/androbugs.exe`` — the compiled Windows standalone
- ``$ANDROBUGS_HOME/androbugs.py`` — the canonical Unix script
- ``$ANDROBUGS_HOME/AndroBugs.py`` — the CamelCase variant some forks ship

OS prerequisite: the AndroBugs checkout under ``$ANDROBUGS_HOME``, plus a
Python 2.7 interpreter on PATH (skipped when invoking the .exe). The
upstream project never migrated to Python 3 — operators that don't have
Python 2.7 install the prebuilt Windows release instead.

Acceptance shape per PRD §A-5:
    dict with:
        ``package_name`` (str | None) — extracted from the report header
        ``report_path`` (str | None) — absolute path to the produced
            ``.txt`` file, preserved only when ``output_dir`` was supplied
        ``vulnerabilities`` (list[dict]) — findings at
            ``Critical`` / ``Warning`` / ``Notice`` levels
        ``info`` (list[dict]) — findings at ``Info`` level (clean
            ``Did not detect ...`` entries)
        Each finding row:
            ``vector_id`` (str)  — stable AndroBugs tag (e.g. ``WEBVIEW_RCE``)
            ``level`` (str)      — Critical / Warning / Notice / Info
            ``summary`` (str)    — one-line description
            ``tags`` (list[str]) — auxiliary categories (``"WebView"``,
                ``"SSL_Security"``, etc.) lifted from the ``<tag>`` block
            ``cve`` (str | None) — CVE id when the rule cites one
            ``title`` (str)      — full description body (multi-line)
            ``details`` (str)    — call-site / source-class list
                (multi-line; empty for ``Info`` rows)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Wall-clock cap per AndroBugs run. The README claims <2min average on a
# typical APK; 300s gives generous headroom for larger customer apps
# without parking the worker indefinitely. The orchestration layer's
# per-tool semaphore bounds total concurrency on top of this.
_DEFAULT_TIMEOUT_S = 300

_ANDROBUGS_HOME_ENV = "ANDROBUGS_HOME"

_INSTALL_HINT = (
    f"AndroBugs Framework not configured. Set {_ANDROBUGS_HOME_ENV} to the "
    "AndroBugs Framework checkout (https://github.com/AndroBugs/AndroBugs_Framework). "
    "Expected layout: $ANDROBUGS_HOME/androbugs.py (Python 2.7 source on Unix) "
    "or $ANDROBUGS_HOME/androbugs.exe (compiled standalone on Windows). "
    "Upstream never migrated to Python 3, so a Python 2.7 interpreter must "
    "be on PATH when running from source."
)

_LEVEL_INFO = "Info"
_LEVELS = ("Critical", "Warning", "Notice", _LEVEL_INFO)

# Finding header line — emitted by AndroBugs's ``load_to_output_list``:
#   [%s] %s %s (Vector ID: %s):
# where the three ``%s`` slots are level, extra-tag block, and summary.
# The ``(Vector ID: ...)`` suffix only appears when ``--show_vector_id``
# is set (we always pass it). Captures the whole post-level segment as
# ``rest``; the helper below splits the trailing vector + leading tags.
_FINDING_HEADER_RE = re.compile(
    r"^\[(?P<level>Critical|Warning|Notice|Info)\]\s*(?P<rest>.+?):\s*$",
)

# Trailing ``(Vector ID: TAG)`` block, searched from the right. The
# bracket-balanced character class (``[^)]+``) is enough — Vector IDs
# never embed a closing paren.
_VECTOR_TAIL_RE = re.compile(r"\s*\(Vector\s+ID:\s*(?P<vid>[^)]+)\)\s*$")

# Leading ``<tag1><tag2><#CVE-...#>`` cluster between the level marker
# and the human-readable summary. AndroBugs concatenates tag tokens
# without separators, so a greedy group of ``<...>`` repeats captures
# the whole cluster in one shot.
_EXTRA_TAGS_RE = re.compile(r"^((?:<[^>]+>)+)")

# Individual tag inside ``<...>`` — either a plain category name or a
# CVE id wrapped in ``#`` markers (e.g. ``<#CVE-2013-4710#>``).
_SINGLE_TAG_RE = re.compile(r"<([^>]+)>")
_CVE_TAG_RE = re.compile(r"^#(?P<cve>CVE-\d{4}-\d+)#$", re.IGNORECASE)

# Section dividers AndroBugs emits between header, body, and trailer.
# Length is consistent at 60 dashes, but we accept any run >= 20 to
# tolerate version drift / custom forks.
_HORIZONTAL_RULE_RE = re.compile(r"^-{20,}$")

# Trailer lines that mark the end of finding output. ``<<<\s*Analysis``
# is the "stored to disk" announcement that may appear under one of the
# REPORT_OUTPUT modes; defensive include.
_TRAILER_LINE_RE = re.compile(
    r"^(AndroBugs analyzing time|Total elapsed time|<<<\s*Analysis)",
)

# Detail-line indent threshold. AndroBugs's TextWrapper writes titles
# with an 11-space initial indent and details with 15-space initial
# indent (20-space subsequent). Any line indented 15+ spaces belongs
# to the detail block; below that it's the title body.
_DETAIL_INDENT_THRESHOLD = 15


def register(mcp: Any) -> None:
    @mcp.tool()
    async def androbugs_scan(
        apk_path: str,
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        """Run AndroBugs Framework static rules over an APK.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.
                AndroBugs reads the manifest plus DEX bytecode directly —
                no separate decode step required.
            output_dir: Where AndroBugs should write its ``.txt`` report.
                When ``None`` (default), a temp directory holds the
                report for the duration of the call and is removed
                after parsing. When set, the directory is created if
                missing and the file is preserved at
                ``<output_dir>/<package_name>_<signature>.txt`` so the
                operator can re-read it later. Paths under
                ``~/`` and relative paths are both resolved.

        Returns:
            Parsed report dict in the documented shape.

        Raises:
            FileNotFoundError: ``apk_path`` does not exist, ``output_dir``
                cannot be created, or no AndroBugs entrypoint
                (``androbugs.exe`` / ``androbugs.py`` / ``AndroBugs.py``)
                is present under ``$ANDROBUGS_HOME``.
            ValueError: ``apk_path`` exists but is not a regular file.
            RuntimeError: ``ANDROBUGS_HOME`` env var is unset, the
                subprocess timed out, AndroBugs exited non-zero, or no
                report file materialised in the output directory.
        """
        home = os.environ.get(_ANDROBUGS_HOME_ENV)
        if not home:
            raise RuntimeError(_INSTALL_HINT)

        invocation = _resolve_invocation(home)

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        if output_dir is None:
            with tempfile.TemporaryDirectory(prefix="androbugs-report-") as tmp:
                report_dir = Path(tmp)
                return await _run_and_parse(
                    invocation, apk, report_dir, preserve=False,
                )

        report_dir = Path(output_dir).expanduser().resolve()
        report_dir.mkdir(parents=True, exist_ok=True)
        return await _run_and_parse(
            invocation, apk, report_dir, preserve=True,
        )


def _resolve_invocation(home: str) -> list[str]:
    """Resolve the prefix argv for invoking AndroBugs.

    Returns the partial command (no ``-f`` / ``-o`` / ``-v`` yet). Prefers
    the Windows standalone when present because it bundles its own Python
    2.7 runtime; falls back to ``python <script>`` otherwise.

    Raises:
        FileNotFoundError: ``ANDROBUGS_HOME`` does not resolve to an
            existing directory, or none of the expected entrypoints
            are present under it.
    """
    home_dir = Path(home).expanduser().resolve()
    if not home_dir.is_dir():
        raise FileNotFoundError(
            f"{_ANDROBUGS_HOME_ENV} does not exist or is not a directory: {home_dir}",
        )

    exe = home_dir / "androbugs.exe"
    if exe.is_file():
        return [str(exe)]

    for script_name in ("androbugs.py", "AndroBugs.py"):
        script = home_dir / script_name
        if script.is_file():
            # Prefer ``python2`` when present; fall back to plain
            # ``python`` and let the operator's PATH pick. AndroBugs
            # crashes on Python 3 imports (``ConfigParser``), so this
            # is the operator's tripwire to fix their environment if
            # they aimed it at Python 3.
            python_bin = (
                shutil.which("python2")
                or shutil.which("python2.7")
                or shutil.which("python")
                or "python"
            )
            return [python_bin, str(script)]

    raise FileNotFoundError(
        f"AndroBugs entrypoint not found under {home_dir}; expected "
        "androbugs.exe, androbugs.py, or AndroBugs.py",
    )


async def _run_and_parse(
    invocation: list[str],
    apk: Path,
    report_dir: Path,
    *,
    preserve: bool,
) -> dict[str, Any]:
    """Shell out, wait, locate the produced report, and project it.

    ``preserve`` controls whether ``report_path`` is surfaced back to the
    caller. When the tempdir path is used, the file is gone after the
    ``with`` block exits so returning the path would be misleading.
    """
    cmd: list[str] = [
        *invocation,
        "-f", str(apk),
        "-o", str(report_dir),
        # Always emit Vector IDs — the parser keys on them. AndroBugs's
        # default omits them, which would force a brittle title-based
        # match against rule descriptions.
        "-v",
    ]

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
            f"androbugs timed out after {_DEFAULT_TIMEOUT_S}s on {apk}",
        ) from exc

    if proc.returncode != 0:
        stderr_blob = (proc.stderr or "").strip()
        raise RuntimeError(
            f"androbugs exited {proc.returncode}: "
            f"{stderr_blob or '<no stderr>'}",
        )

    report_path = _find_report_file(report_dir)
    if report_path is None:
        raise RuntimeError(
            f"androbugs did not produce a .txt report under {report_dir}; "
            f"stdout was: {(proc.stdout or '').strip() or '<empty>'}",
        )

    try:
        raw = report_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(
            f"could not read androbugs report at {report_path}: {exc}",
        ) from exc

    parsed = _parse_androbugs_report(raw)
    return {
        "package_name": parsed["package_name"],
        "report_path": str(report_path) if preserve else None,
        "vulnerabilities": parsed["vulnerabilities"],
        "info": parsed["info"],
    }


def _find_report_file(report_dir: Path) -> Path | None:
    """Return the newest ``.txt`` AndroBugs report under ``report_dir``.

    AndroBugs names its file ``<package_name>_<signature>.txt``. We glob
    rather than predict the name because the signature is hashed from
    a timestamp + random seed and is not knowable in advance.
    """
    candidates = sorted(
        report_dir.glob("*.txt"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _parse_androbugs_report(raw: str) -> dict[str, Any]:
    """Project an AndroBugs report text into the documented finding shape.

    The report has three sections separated by ``--------...`` rules:

        1. Banner + package metadata (``Package Name:``, hashes, SDK)
        2. Findings — one block per Vector ID, sorted by severity
        3. Timing trailer (``AndroBugs analyzing time:`` etc.)

    Each finding block opens with a header line that this parser keys on:

        ``[Level] <tag><tag><#CVE-...#> Summary (Vector ID: TAG):``

    Subsequent indented lines are accumulated into the ``title`` or
    ``details`` field based on indent depth (11 vs 15+ spaces).
    """
    package_name: str | None = None
    vulnerabilities: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []

    current: dict[str, Any] | None = None
    body_lines: list[str] = []

    def _flush() -> None:
        nonlocal current, body_lines
        if current is None:
            return
        title, details = _split_title_details(body_lines)
        current["title"] = title
        current["details"] = details
        if current["level"] == _LEVEL_INFO:
            info.append(current)
        else:
            vulnerabilities.append(current)
        current = None
        body_lines = []

    for raw_line in raw.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()

        if package_name is None and stripped.startswith("Package Name:"):
            package_name = stripped.split(":", 1)[1].strip() or None

        if _TRAILER_LINE_RE.match(stripped):
            _flush()
            # Past the timing trailer; subsequent lines are housekeeping
            # noise and never new findings. Continue iterating defensively
            # but stop accumulating into a body.
            continue

        if _HORIZONTAL_RULE_RE.match(stripped):
            # Section dividers separate the banner, body, and trailer.
            # They are never part of a finding's content.
            _flush()
            continue

        header_match = _FINDING_HEADER_RE.match(stripped)
        if header_match:
            _flush()
            current = _build_finding_from_header(header_match)
            body_lines = []
            continue

        if current is not None:
            body_lines.append(line)

    _flush()

    return {
        "package_name": package_name,
        "vulnerabilities": vulnerabilities,
        "info": info,
    }


def _build_finding_from_header(match: re.Match[str]) -> dict[str, Any]:
    """Project a matched header line into the finding skeleton dict.

    Splits ``rest`` (everything between ``[Level]`` and the trailing
    ``:``) into vector id, extra tags, CVE, and summary.
    """
    level = match.group("level")
    rest = match.group("rest")

    vector_id = ""
    vector_match = _VECTOR_TAIL_RE.search(rest)
    if vector_match:
        vector_id = vector_match.group("vid").strip()
        rest = rest[: vector_match.start()].rstrip()

    tags: list[str] = []
    cve: str | None = None
    extras_match = _EXTRA_TAGS_RE.match(rest)
    if extras_match:
        extras = extras_match.group(1)
        for piece in _SINGLE_TAG_RE.findall(extras):
            cve_match = _CVE_TAG_RE.match(piece)
            if cve_match:
                cve = cve_match.group("cve")
            else:
                tags.append(piece)
        rest = rest[extras_match.end():]

    summary = rest.strip()
    return {
        "vector_id": vector_id,
        "level": level,
        "summary": summary,
        "tags": tags,
        "cve": cve,
    }


def _split_title_details(body_lines: list[str]) -> tuple[str, str]:
    """Split a finding body into the title block and the details block.

    AndroBugs's ``load_to_output_list`` writes the title with ``11``
    space initial indent and the details with ``15``+ space indent.
    Once we see the first detail-indented line, everything from there
    forward is detail content. Leading column alignment is stripped on
    output — the caller wants the content, not the wrapping artefacts.
    """
    title_lines: list[str] = []
    detail_lines: list[str] = []
    in_details = False
    for line in body_lines:
        leading = len(line) - len(line.lstrip())
        if leading >= _DETAIL_INDENT_THRESHOLD:
            in_details = True
        stripped = line.strip()
        if not stripped:
            continue
        if in_details:
            detail_lines.append(stripped)
        else:
            title_lines.append(stripped)
    return ("\n".join(title_lines), "\n".join(detail_lines))
