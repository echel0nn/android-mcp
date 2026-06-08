"""apksigner wrapper — verify APK Signature Scheme versions, signers, and lineage.

`apksigner` is the Java tool that AOSP ships under Android SDK
build-tools. It is the authoritative reference for APK signing scheme
verification — APK Signature Scheme v1 (JAR signing), v2 (whole-file),
v3 (key rotation), v3.1 (v3 with rotation targeting API 33+), and v4
(streaming, separate `.idsig` sidecar).

OS prerequisite: `apksigner` on PATH. Install via the Android SDK
manager (`sdkmanager 'build-tools;34.0.0'`) and add
`<sdk>/build-tools/<ver>/` to PATH. On Linux distros a system
`apksigner` package is also fine.

Why this tool exists: signing scheme drift is a load-bearing security
signal. An APK still signed only under v1 (JAR signing) is vulnerable
to the Janus exploit (CVE-2017-13156) on API levels below 26 — an
external party can append a DEX prologue to the APK and the platform
installer accepts it because v1 only signs the central directory, not
the prefix bytes. A reviewer needs to see the scheme set at a glance,
not have to invoke apksigner manually and parse its prose output.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Wall-clock cap for the apksigner subprocess. apksigner reads the
# whole APK to validate central-directory hashes; on a 500 MB game APK
# that takes ~10s on warm cache. 60s leaves ample headroom without
# letting a hung child block the worker indefinitely.
_DEFAULT_TIMEOUT_S = 60

# Highest API level where Janus (CVE-2017-13156) reproduces. From API
# 26 onward the installer requires v2 or v3 signing, so v1-only is
# only catastrophic on the long tail of pre-Oreo devices. The warning
# string still flags it because customer-facing apps frequently still
# support API <26.
_JANUS_MAX_API = 25

# apksigner emits "Verified using v<N> scheme (...): true|false". The
# version token allows decimals because v3.1 was added in Android 13.
_SCHEME_RE = re.compile(
    r"^Verified using v(\d+(?:\.\d+)?) scheme \(.*\): (true|false)\s*$",
)

# Signer DN/digest lines, top-level (the actual signer of the APK).
_SIGNER_DN_RE = re.compile(r"^Signer #(\d+) certificate DN: (.+)$")
_SIGNER_SHA256_RE = re.compile(
    r"^Signer #(\d+) certificate SHA-256 digest: ([a-fA-F0-9]+)\s*$",
)

# Lineage block header — emitted once per signer that has a v3
# SigningCertificateLineage. The number is the count INCLUDING the
# current signer, so a value of N means N-1 historical predecessors.
_LINEAGE_HEADER_RE = re.compile(
    r"^Lineage for signer #(\d+) contains (\d+) certificates?\s*$",
)

# Per-lineage-entry lines. apksigner numbers them from 0 (oldest) to
# count-1 (current signer, identical to the top-level signer).
_LINEAGE_DN_RE = re.compile(r"^Lineage signer #(\d+) certificate DN: (.+)$")
_LINEAGE_SHA256_RE = re.compile(
    r"^Lineage signer #(\d+) certificate SHA-256 digest: ([a-fA-F0-9]+)\s*$",
)


def register(mcp: Any) -> None:
    @mcp.tool()
    async def verify_apk_signing(apk_path: str) -> dict[str, Any]:
        """Verify an APK's signing schemes via `apksigner verify`.

        Runs `apksigner verify --verbose --print-certs <apk_path>` and
        parses the human-readable output into structured fields.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.

        Returns:
            dict with:
                `verified` (bool) — overall verification status
                `apk_path` (str) — resolved absolute path
                `schemes` (list[str]) — schemes actually used, e.g.
                    `["v1", "v2", "v3"]`
                `signers` (list[dict]) — one entry per signer with
                    `subject`, `sha256`, and `lineage_predecessors`
                    (a list of `{subject, sha256}` for v3 rotation
                    history, oldest first; empty when no lineage)
                `warnings` (list[str]) — every `WARNING:` / `ERROR:`
                    line from apksigner plus the synthesized Janus
                    warning when only v1 signing is present

            An APK that fails verification does NOT raise — it returns
            `verified=False` with apksigner's own ERROR lines in
            `warnings`. The caller decides whether to treat that as
            blocking.

        Raises:
            FileNotFoundError: APK path does not exist.
            ValueError: APK path is a directory.
            RuntimeError: `apksigner` is not on PATH, or the subprocess
                timed out.
        """
        apksigner = shutil.which("apksigner")
        if apksigner is None:
            raise RuntimeError(
                "apksigner not on PATH. Install from the Android SDK "
                "build-tools (sdkmanager 'build-tools;34.0.0') and add "
                "<sdk>/build-tools/<ver>/ to PATH.",
            )

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        cmd = [apksigner, "verify", "--verbose", "--print-certs", str(apk)]
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
                f"apksigner timed out after {_DEFAULT_TIMEOUT_S}s on {apk}",
            ) from exc

        # apksigner exits 0 only when the signature verifies end-to-end.
        # A non-zero exit still produces useful diagnostic output, so
        # parse first, decide later.
        verified = proc.returncode == 0
        schemes, signers, warnings = _parse_apksigner_output(
            proc.stdout, proc.stderr,
        )

        if verified and schemes == ["v1"]:
            warnings.append(
                f"v1-only signing - vulnerable to Janus "
                f"(CVE-2017-13156) on API <={_JANUS_MAX_API}",
            )

        return {
            "verified": verified,
            "apk_path": str(apk),
            "schemes": schemes,
            "signers": signers,
            "warnings": warnings,
        }


def _parse_apksigner_output(
    stdout: str,
    stderr: str,
) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    """Parse `apksigner verify --verbose --print-certs` output.

    The parser is intentionally tolerant: unknown lines are skipped,
    and a signer block missing its SHA-256 digest still surfaces (with
    `sha256=""`). Strictness would just turn benign apksigner version
    skew into a 500.
    """
    schemes_seen: list[str] = []
    # signer_idx -> {subject, sha256, lineage_predecessors}
    signers_by_idx: dict[int, dict[str, Any]] = {}
    # While inside a "Lineage for signer #N" block we route lineage
    # lines to that signer. None means "not currently in a lineage block".
    current_lineage_signer: int | None = None
    # (signer_idx, lineage_entry_idx) -> {subject, sha256}
    lineage_entries: dict[tuple[int, int], dict[str, Any]] = {}
    warnings: list[str] = []

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue

        # Scheme line — version token may include a decimal (v3.1).
        m = _SCHEME_RE.match(line)
        if m:
            version, ok = m.group(1), m.group(2)
            if ok == "true":
                schemes_seen.append(f"v{version}")
            continue

        # Lineage block header — switches state for subsequent lines.
        m = _LINEAGE_HEADER_RE.match(line)
        if m:
            current_lineage_signer = int(m.group(1))
            signers_by_idx.setdefault(current_lineage_signer, {}).setdefault(
                "lineage_predecessors", [],
            )
            continue

        # Lineage-entry DN. Only meaningful while inside a lineage block.
        m = _LINEAGE_DN_RE.match(line)
        if m and current_lineage_signer is not None:
            key = (current_lineage_signer, int(m.group(1)))
            lineage_entries.setdefault(key, {})["subject"] = m.group(2)
            continue

        # Lineage-entry SHA-256. Same routing rule.
        m = _LINEAGE_SHA256_RE.match(line)
        if m and current_lineage_signer is not None:
            key = (current_lineage_signer, int(m.group(1)))
            lineage_entries.setdefault(key, {})["sha256"] = m.group(2).lower()
            continue

        # Top-level signer DN — exits any active lineage state.
        m = _SIGNER_DN_RE.match(line)
        if m:
            current_lineage_signer = None
            signers_by_idx.setdefault(int(m.group(1)), {})["subject"] = m.group(2)
            continue

        # Top-level signer SHA-256.
        m = _SIGNER_SHA256_RE.match(line)
        if m:
            current_lineage_signer = None
            signers_by_idx.setdefault(int(m.group(1)), {})["sha256"] = (
                m.group(2).lower()
            )
            continue

        if line.startswith("WARNING:"):
            warnings.append(line)

    # apksigner sends some diagnostics to stderr. Pull WARNING/ERROR
    # rows from there as well — the schema is symmetric.
    for raw in stderr.splitlines():
        line = raw.strip()
        if line.startswith("WARNING:") or line.startswith("ERROR:"):
            warnings.append(line)

    # Roll up lineage entries into each signer, ordered by entry index
    # (oldest predecessor first). The current signer (last entry,
    # whose SHA-256 typically matches the top-level signer) is dropped
    # to keep the list strictly historical.
    by_signer: dict[int, list[dict[str, Any]]] = {}
    for (signer_idx, lin_idx), entry in lineage_entries.items():
        by_signer.setdefault(signer_idx, []).append((lin_idx, entry))
    for signer_idx, items in by_signer.items():
        items.sort(key=lambda pair: pair[0])
        # Drop the trailing entry when its SHA-256 matches the
        # top-level signer's — that entry IS the current signer
        # appearing in the lineage list. Keeps `lineage_predecessors`
        # strictly about historical signers.
        top_sha = signers_by_idx.get(signer_idx, {}).get("sha256", "")
        predecessors = [entry for _, entry in items]
        if top_sha and predecessors and predecessors[-1].get("sha256") == top_sha:
            predecessors = predecessors[:-1]
        signers_by_idx.setdefault(signer_idx, {})["lineage_predecessors"] = (
            predecessors
        )

    signers: list[dict[str, Any]] = []
    for idx in sorted(signers_by_idx.keys()):
        info = signers_by_idx[idx]
        signers.append(
            {
                "subject": info.get("subject", ""),
                "sha256": info.get("sha256", ""),
                "lineage_predecessors": info.get("lineage_predecessors", []),
            },
        )

    return schemes_seen, signers, warnings
