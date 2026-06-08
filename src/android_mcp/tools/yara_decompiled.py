"""YARA wrapper — scan a jadx-decompiled tree against a YARA ruleset.

When jadx is done, the operator is left with a tree of `.java`, `.xml`,
`.properties`, `.smali`, and resource files. The two questions reviewers
ask of that tree are:

    1. "Does any literal in here match a known-bad pattern?" — hardcoded
       AWS keys, Google API keys, PEM private-key blocks, JWTs.
    2. "Does any code shape match a known-bad construct?" — debug Log
       calls in shipped code, ECB-mode Cipher, no-op TrustManager.

YARA answers both in one pass against a single ruleset file. This
wrapper compiles the ruleset, walks every file under `decompiled_dir`
(skipping binary blobs the ruleset will never match anyway), and
projects each `yara.Match` onto the per-tool response shape the
acceptance criterion documents.

Ships a default ruleset at ``data/rules/android_basic.yar`` covering
the three buckets above; the caller can override by passing
``ruleset_path`` to a site-specific .yar file.

Acceptance shape per PRD §A-7:
    list of dicts, each with:
        rule_name (str)      — YARA rule identifier
        file (str)           — absolute path of the matching file
        tags (list[str])     — tags declared on the rule
        meta (dict)          — rule metadata block as a flat dict
        strings (list[dict]) — per-string matches, each with:
            identifier (str)    — YARA string identifier (e.g. ``$aws``)
            offset (int)        — byte offset of the match in the file
            data_preview (str)  — matched bytes, decoded utf-8 errors
                                  replaced, truncated to 80 bytes
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterator

_log = logging.getLogger(__name__)

# Bundled-ruleset location. ``__file__`` is
# ``src/android_mcp/tools/yara_decompiled.py``; the ruleset lives at
# ``src/android_mcp/data/rules/android_basic.yar`` so two ``parent``
# hops land us at the package root.
_DEFAULT_RULESET = (
    Path(__file__).resolve().parent.parent / "data" / "rules" / "android_basic.yar"
)

# Preview cap, in bytes. YARA reports matched bytes verbatim; for
# high-entropy hits or long string literals that can be hundreds of
# bytes. 80 is enough to identify what matched without bloating the
# response payload.
_PREVIEW_CAP = 80

# Cap on per-match string-instance count. A regex like the JWT one
# fires on every JWT-shaped substring; capping at 50 per match keeps
# pathological files from producing tens-of-thousands-long lists
# while still surfacing every distinct pattern.
_MATCHES_PER_RULE_CAP = 50

# Per-file size cap. Walking multi-megabyte binary resources through
# YARA produces noise (the bundled rules look for ASCII patterns)
# and burns wall-clock. 8 MiB is large enough to cover normal Java
# sources, smali, and XML, while bounded against accidental
# scans of huge resource files.
_FILE_SIZE_CAP = 8 * 1024 * 1024

# Binary extensions that the bundled ruleset will never match
# usefully. Skipping them removes noise and shaves the scan time
# on large jadx output trees.
_SKIP_EXTENSIONS = frozenset({
    # Compiled bytecode and shared objects.
    ".dex", ".odex", ".so", ".class",
    # Containers.
    ".apk", ".jar", ".zip", ".aar", ".war",
    # Images / fonts / media.
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ico",
    ".mp3", ".mp4", ".m4a", ".ogg", ".webm", ".wav",
    ".ttf", ".otf", ".woff", ".woff2",
    # Binary serialized resources.
    ".arsc",
})

# Directory names whose contents are virtually always machine output
# the reviewer should not be auditing.
_SKIP_DIRS = frozenset({
    ".git", ".gradle", ".idea", "build", "node_modules", "__pycache__",
})


def register(mcp: Any) -> None:
    @mcp.tool()
    async def yara_scan_dir(
        decompiled_dir: str,
        ruleset_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Scan every file under ``decompiled_dir`` with a YARA ruleset.

        Args:
            decompiled_dir: Root of a tree to scan. Typically a
                jadx-decompiled output directory, but any tree of
                source/text files works.
            ruleset_path: Optional path to a YARA rules file. When
                ``None``, the bundled ``android_basic.yar`` ruleset
                is compiled instead (hardcoded-secrets, debug-flags,
                unsafe-crypto rule buckets).

        Returns:
            One dict per ``(rule, file)`` match. Empty list when
            nothing matched. See the module docstring for the
            documented response shape.

        Raises:
            FileNotFoundError: ``decompiled_dir`` does not exist, or
                ``ruleset_path`` was supplied but does not exist.
            ValueError: ``decompiled_dir`` exists but is not a
                directory, or ``ruleset_path`` failed YARA's syntax
                check.
        """
        import yara  # local import keeps cold-start fast

        root = Path(decompiled_dir).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"decompiled_dir not found: {root}")
        if not root.is_dir():
            raise ValueError(f"decompiled_dir is not a directory: {root}")

        rules_path = (
            Path(ruleset_path).expanduser().resolve()
            if ruleset_path
            else _DEFAULT_RULESET
        )
        if not rules_path.exists():
            raise FileNotFoundError(f"ruleset not found: {rules_path}")

        try:
            rules = yara.compile(filepath=str(rules_path))
        except yara.SyntaxError as exc:
            raise ValueError(f"yara compile failed for {rules_path}: {exc}") from exc

        results: list[dict[str, Any]] = []
        for file_path in _iter_scan_targets(root):
            try:
                matches = rules.match(filepath=str(file_path))
            except (yara.Error, OSError) as exc:
                # Individual file failures must not abort the scan;
                # log and move on so a single unreadable file does
                # not poison the whole jadx tree.
                _log.debug("yara match failed for %s: %s", file_path, exc)
                continue
            for match in matches:
                results.append(_project_match(match, file_path))
        return results


def _iter_scan_targets(root: Path) -> Iterator[Path]:
    """Yield files under ``root`` that are worth feeding to YARA.

    Filters applied (in order, cheapest first):
        - skip non-files (directories, symlinks to dirs)
        - skip files whose extension is in ``_SKIP_EXTENSIONS``
        - skip files inside any ``_SKIP_DIRS`` directory at any depth
        - skip files larger than ``_FILE_SIZE_CAP``
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


def _project_match(match: Any, file_path: Path) -> dict[str, Any]:
    """Project one ``yara.Match`` onto the documented response dict."""
    return {
        "rule_name": getattr(match, "rule", ""),
        "file": str(file_path),
        "tags": list(getattr(match, "tags", []) or []),
        "meta": dict(getattr(match, "meta", {}) or {}),
        "strings": _project_strings(match),
    }


def _project_strings(match: Any) -> list[dict[str, Any]]:
    """Project a ``yara.Match.strings`` payload into ``[{identifier,
    offset, data_preview}, ...]``, capped at ``_MATCHES_PER_RULE_CAP``.

    yara-python 4.3+ exposes ``match.strings`` as a list of
    ``StringMatch`` objects with ``.identifier`` and ``.instances``
    (a list of ``StringMatchInstance`` with ``.offset`` and
    ``.matched_data``). Older 4.0-4.2 returned 3-tuples
    ``(offset, identifier, data)``. Both shapes are tolerated so a
    pin bump does not silently break this tool.
    """
    out: list[dict[str, Any]] = []
    cap = _MATCHES_PER_RULE_CAP
    for s in getattr(match, "strings", []) or []:
        if len(out) >= cap:
            break
        if isinstance(s, tuple):
            # yara-python <= 4.2 legacy shape.
            offset, identifier, data = s
            out.append({
                "identifier": identifier,
                "offset": int(offset),
                "data_preview": _preview(data),
            })
            continue
        identifier = getattr(s, "identifier", "")
        instances = getattr(s, "instances", None) or [s]
        for inst in instances:
            if len(out) >= cap:
                break
            offset = getattr(inst, "offset", 0)
            data = getattr(inst, "matched_data", b"")
            out.append({
                "identifier": identifier,
                "offset": int(offset),
                "data_preview": _preview(data),
            })
    return out


def _preview(data: Any) -> str:
    """Stringify matched bytes for the response payload.

    Bytes are decoded utf-8 with errors replaced (so non-ASCII matches
    don't crash the wire format) and truncated to ``_PREVIEW_CAP``.
    Non-bytes values are stringified, also truncated.
    """
    if isinstance(data, (bytes, bytearray)):
        snippet = bytes(data[:_PREVIEW_CAP])
        return snippet.decode("utf-8", errors="replace")
    return str(data)[:_PREVIEW_CAP]
