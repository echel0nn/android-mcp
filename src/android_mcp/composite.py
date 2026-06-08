"""Composite analysis — higher-level audit primitives.

Aggregates the per-tool wrappers under ``tools/`` into reasoning-friendly
shapes that mirror audit-mcp's composite layer. VR personas call these
directly instead of stitching the underlying per-tool wrappers
manually.

Implemented so far:

    find_secrets    — hardcoded credentials / API keys / PEM blocks /
                      JWTs / Firebase URLs across a decompiled tree
                      plus an optional extra assets dir.

Reserved per PRD §A-10..A-12 for follow-up iterations:

    verify_capabilities
    classify_behavior
    compute_risk_score

Each composite handler is registered via :func:`register` and follows
the same one-file-per-tool style as ``tools/<name>.py`` so the rest of
the server (``http_api._build_tool_index``, the FastMCP introspection
endpoints, AILA's bridge) treats it identically.
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any, Iterator

_log = logging.getLogger(__name__)

# Context window emitted per finding. 80 bytes is the documented
# acceptance contract — wide enough to identify the surrounding code
# without bloating the response payload across thousands of findings.
_CONTEXT_BYTES = 80

# Shannon-entropy floor (bits-per-byte) for the entropy-gated patterns.
# Below this, a candidate match is dropped as an English-text or
# repeating-bytes lookalike. 4.5 is the conventional cutoff (truecrypto
# / detect-secrets / trufflehog all sit in [4.3, 5.0]).
_ENTROPY_MIN_BITS = 4.5

# Per-file size cap. Resource blobs above this are almost always
# binary assets the regex set will never match usefully (PNGs, OTF
# fonts, DEX files). 8 MiB matches yara_decompiled's cap.
_FILE_SIZE_CAP = 8 * 1024 * 1024

# Per-file finding cap. Pathological resource files (base64 dumps,
# minified bundles) can fire the generic-bearer rule thousands of
# times; capping keeps the response bounded.
_MATCHES_PER_FILE_CAP = 100

# Binary extensions that the regex set never matches usefully.
# Mirrors yara_decompiled's skip list — both modules walk the same
# kind of jadx/apktool output tree.
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".mp3", ".mp4", ".wav", ".ogg", ".m4a", ".aac",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".dex", ".odex", ".so", ".jar", ".aar", ".apk",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf",
    ".pyc", ".pyo",
    ".class",
})

# Directory names whose contents are machine output or VCS state — no
# point scanning them.
_SKIP_DIRS = frozenset({
    ".git", ".gradle", ".idea", "build", "node_modules", "__pycache__",
})

# Hardcoded-pattern table.
#
# Each entry is ``(kind, compiled_regex, needs_entropy_check,
# redact_as_marker)``. When ``needs_entropy_check`` is True the
# Shannon-entropy filter runs against the matched bytes, dropping
# <4.5 bits-per-byte patterns that accidentally fit the shape
# (English prose, repeating-char placeholders, lorem-ipsum filler).
# When ``redact_as_marker`` is True the redacted output keeps the
# full match verbatim — for purely structural indicators (PEM block
# headers, Firebase URLs) where the matched bytes are public-
# knowledge markers, not the credential themselves; the credential
# itself sits in the surrounding context, not in the match span.
#
# Patterns intentionally operate on bytes so the same regex applies
# uniformly across UTF-8 source files, ASCII XML, and Latin-1
# strings.xml resources without re-decoding per call.
_PATTERNS: tuple[tuple[str, re.Pattern[bytes], bool, bool], ...] = (
    # AWS Access Key ID — 16 char body after `AKIA` prefix; the
    # prefix itself rules out false-positive English text. Body is
    # the credential, so redact.
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}"), False, False),
    # Google API key — `AIza` + 35 URL-safe base64 chars. Documented
    # by Google's developer guides; used by Firebase, Maps, Places.
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), False, False),
    # JWT — three URL-safe base64 segments separated by dots.
    # `eyJ` is the deterministic start of any header that begins
    # with the `{"alg"` JSON, which all JWTs do.
    (
        "jwt_token",
        re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        False,
        False,
    ),
    # PEM private key block headers. The encrypted variant fires
    # too, since seeing one in an APK is a finding regardless. The
    # marker itself is structural — keep it visible so the
    # reviewer sees which variant (RSA / EC / ENCRYPTED) fired.
    (
        "pem_private_key",
        re.compile(
            rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"
        ),
        False,
        True,
    ),
    # Firebase Realtime Database / Hosting / App URL — the
    # presence of one is benign on its own, but it locates the
    # backend a reviewer needs to check for open ruleset. The URL
    # is a public-knowledge marker; keep it visible.
    (
        "firebase_url",
        re.compile(
            rb"https?://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app|firebaseapp\.com)/"
        ),
        False,
        True,
    ),
    # Generic high-entropy bearer / API key. Catches arbitrary
    # vendor tokens the four shape-anchored patterns miss. Gated
    # by the entropy filter — without it this fires on every
    # base64-padded image data URI and every long English run.
    (
        "generic_bearer",
        re.compile(rb"[A-Za-z0-9_\-+/=]{24,}"),
        True,
        False,
    ),
)


def register(mcp: Any) -> None:
    @mcp.tool()
    async def find_secrets(
        decompiled_dir: str,
        assets_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        """Scan a decompiled APK tree (plus optional assets dir) for hardcoded secrets.

        Walks every text file under ``decompiled_dir`` and (when
        supplied and not already a sub-path) ``assets_dir``, applies
        the bundled hardcoded-pattern set, and projects each match
        onto a uniform ``{file, line, kind, redacted_match,
        context_80b}`` shape.

        Args:
            decompiled_dir: Root of a jadx or apktool output tree. The
                walker recurses into every subdirectory, including
                ``res/values/strings.xml``, so callers do not need to
                point at a specific subdirectory.
            assets_dir: Optional path to an extra assets directory.
                When the apktool ``assets/`` lives outside the
                ``decompiled_dir`` (e.g. apktool decoded resources
                separately from jadx's java output), pass it here.
                Skipped silently if it does not exist; ignored if it
                is already a sub-path of ``decompiled_dir`` so the
                same tree never scans twice.

        Returns:
            Flat list of ``{file, line, kind, redacted_match,
            context_80b}`` dicts. Empty list when nothing matched.
            ``file`` is the absolute path as a string. ``line`` is
            1-indexed. ``redacted_match`` shows enough of the match
            for the reviewer to recognise the secret without putting
            the full credential into a chat/log payload.

        Raises:
            FileNotFoundError: ``decompiled_dir`` does not exist.
            ValueError: ``decompiled_dir`` exists but is not a
                directory.
        """
        roots = _resolve_roots(decompiled_dir, assets_dir)
        results: list[dict[str, Any]] = []
        for root in roots:
            for file_path in _iter_scan_targets(root):
                results.extend(_scan_file(file_path))
        return results


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _resolve_roots(decompiled_dir: str, assets_dir: str | None) -> list[Path]:
    """Resolve the two input paths into a deduped list of root dirs to scan.

    ``decompiled_dir`` is required and validated. ``assets_dir`` is
    optional: it is included only when it exists, is a directory, is
    not equal to ``decompiled_dir``, and is not a sub-path of
    ``decompiled_dir`` (avoids double-scanning when the operator
    points both arguments at the same tree).
    """
    d = Path(decompiled_dir).expanduser().resolve()
    if not d.exists():
        raise FileNotFoundError(f"decompiled_dir not found: {d}")
    if not d.is_dir():
        raise ValueError(f"decompiled_dir is not a directory: {d}")
    out: list[Path] = [d]

    if assets_dir:
        a = Path(assets_dir).expanduser().resolve()
        if not a.exists():
            _log.debug("assets_dir does not exist, skipping: %s", a)
        elif not a.is_dir():
            _log.debug("assets_dir is not a directory, skipping: %s", a)
        elif a == d or _is_subpath(a, d):
            _log.debug("assets_dir is already inside decompiled_dir, skipping: %s", a)
        else:
            out.append(a)

    return out


def _is_subpath(child: Path, parent: Path) -> bool:
    """True when ``child`` is at or below ``parent`` in the filesystem tree."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _iter_scan_targets(root: Path) -> Iterator[Path]:
    """Yield files under ``root`` worth feeding to the regex set.

    Filters applied (cheapest first):

    1. skip non-files (directories, symlinks to dirs)
    2. skip files whose extension is in ``_SKIP_EXTENSIONS``
    3. skip files inside any ``_SKIP_DIRS`` directory at any depth
    4. skip files larger than ``_FILE_SIZE_CAP``
    """
    skip_dirs = _SKIP_DIRS
    skip_exts = _SKIP_EXTENSIONS
    size_cap = _FILE_SIZE_CAP
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in skip_exts:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > size_cap:
                continue
        except OSError:
            continue
        yield path


def _scan_file(path: Path) -> list[dict[str, Any]]:
    """Apply every pattern to ``path``'s bytes and return projected findings.

    Reads the file once as bytes, runs each compiled regex via
    ``finditer``, and projects each match onto the documented
    response dict. Entropy-gated patterns drop matches whose
    Shannon entropy falls below ``_ENTROPY_MIN_BITS``.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        _log.debug("failed to read %s: %s", path, exc)
        return []

    out: list[dict[str, Any]] = []
    seen_spans: set[tuple[int, int]] = set()
    for kind, pattern, needs_entropy, redact_as_marker in _PATTERNS:
        for m in pattern.finditer(data):
            if len(out) >= _MATCHES_PER_FILE_CAP:
                return out
            span = m.span()
            # Suppress duplicate spans across patterns — a JWT will
            # often also match the generic-bearer pattern; report it
            # once under the more specific kind (which always runs
            # first in ``_PATTERNS``).
            if span in seen_spans:
                continue
            matched = m.group(0)
            if needs_entropy and _shannon_entropy(matched) < _ENTROPY_MIN_BITS:
                continue
            seen_spans.add(span)
            out.append({
                "file": str(path),
                "line": _line_at_offset(data, span[0]),
                "kind": kind,
                "redacted_match": _redact(matched, as_marker=redact_as_marker),
                "context_80b": _context(data, span[0], span[1]),
            })
    return out


def _line_at_offset(data: bytes, offset: int) -> int:
    """1-indexed line number of byte ``offset`` within ``data``."""
    return data.count(b"\n", 0, offset) + 1


def _context(data: bytes, start: int, end: int) -> str:
    """Extract ``_CONTEXT_BYTES`` of context around a match span.

    Centers the window on the match: half the leftover budget before
    the match, half after, clipped at the file boundaries. The match
    itself is included verbatim in the window (not redacted) so a
    reviewer can see the surrounding code.

    Decoded as UTF-8 with replacement for non-decodable bytes — the
    point is a human-readable preview, not byte-faithful round-trip.
    """
    span = end - start
    if span >= _CONTEXT_BYTES:
        return data[start:start + _CONTEXT_BYTES].decode("utf-8", errors="replace")

    pad_total = _CONTEXT_BYTES - span
    pad_before = pad_total // 2
    win_start = max(0, start - pad_before)
    # Pull the remaining budget from after the match. If we hit the
    # left boundary, all the slack goes to the right side.
    consumed_before = start - win_start
    win_end = min(len(data), end + (pad_total - consumed_before))
    return data[win_start:win_end].decode("utf-8", errors="replace")


def _redact(matched: bytes, *, as_marker: bool = False) -> str:
    """Shorten ``matched`` to a recognisable redacted form.

    For credential-bearing matches (``as_marker=False``, the default):
    keep the leading + trailing 4 chars so a reviewer can spot which
    key they are looking at without copying the full credential into
    a chat log. The middle is replaced with an ellipsis carrying the
    elided character count.

    For purely structural markers (``as_marker=True`` — PEM block
    headers, Firebase URLs): the matched bytes are public-knowledge
    indicators rather than secrets, so keep the full match verbatim
    so the reviewer can see which variant fired.

    For very short matches (≤8 chars — e.g. a generic 8-char token
    surviving an entropy edge case): keep first 2 + last 2 chars.
    """
    s = matched.decode("utf-8", errors="replace")
    if as_marker:
        return s
    n = len(s)
    if n <= 8:
        return f"{s[:2]}...{s[-2:]}"
    head = 4
    tail = 4
    return f"{s[:head]}...({n - head - tail} chars)...{s[-tail:]}"


def _shannon_entropy(data: bytes) -> float:
    """Bits-per-byte Shannon entropy of ``data``.

    Returns 0.0 for an empty buffer. Used as the cheap filter for
    pattern entries flagged ``needs_entropy_check=True`` — drops
    English-text and repeating-char placeholders that accidentally
    fit a high-length URL-safe shape.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)
