"""React Native bundle extraction + decompile + sourcemap-driven slicing.

This tool reads an APK as a zipfile, walks `assets/` for known React
Native bundle filenames, detects Hermes bytecode vs plain JavaScript via
magic-byte sniff, decompiles Hermes via the pure-Python ``hermes_dec``
package, beautifies minified plain JS via ``jsbeautifier``, and SLICES
the result into per-module files so audit-mcp can build a meaningful
function graph instead of indexing one 50 MB blob.

Decisions baked in:
  * **Async-safe.** Every CPU-heavy step (Hermes decompile, beautify,
    tree-sitter slice) runs inside ``asyncio.to_thread`` so the FastMCP
    event loop stays free. Hermes decompile of a 5 MB bundle can take
    30-90 s; without thread offload the loop would be blocked the whole
    time, blocking sibling tool calls.
  * **Content-addressed cache.** Output dir is keyed by SHA256 of the
    bundle bytes (not the APK bytes) so two APK builds shipping the
    SAME bundle reuse the same decompile. ``force=True`` wipes the
    cache.
  * **Multi-level slicing.** Output structure:
      ``decompiled_dir/modules/<name>.js`` — sourcemap-named modules
      when ``.map`` ships alongside the bundle.
      ``decompiled_dir/slices/slice_<NNNN>_<head>.js`` — tree-sitter
      slices at top-level declaration boundaries when no sourcemap or
      a slice exceeds ``MAX_SLICE_LINES``.
      ``decompiled_dir/index.json`` — manifest pointing at every
      produced file with the function names + size + provenance.
  * **No subprocess.** Pure Python all the way down. Hermes uses
    ``hermes_dec``; plain JS uses ``jsbeautifier``; slicing uses
    ``tree_sitter`` + ``tree_sitter_javascript`` (already a transitive
    dep of audit-mcp).
  * **Soft-skip non-RN APKs.** Returns ``{"decompiled_dir": None,
    "bundles_found": []}`` when no bundle is present. Callers (AILA's
    REACT_NATIVE_EXTRACT stage) treat that as a benign skip.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Workspace root mirrors apktool / jadx conventions.
_DEFAULT_WORKDIR = Path(
    os.environ.get("ANDROID_MCP_WORKDIR", "~/.android-mcp/work")
).expanduser()

# Magic-byte prefix that marks a Hermes bytecode bundle. The full header
# is 56 bytes; we only need the first 4 for detection.
_HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

# Bundle filenames RN ships under assets/. The first three are the
# canonical names; the trailing patterns catch RAM-bundle splits.
_BUNDLE_GLOBS: tuple[str, ...] = (
    "assets/index.android.bundle",
    "assets/index.android.bundle.hbc",
    "assets/*.bundle",
    "assets/*.hbc",
    "assets/*.jsbundle",
)

# Slice line budget: target ~3000 lines per output file. The slicer
# coalesces adjacent top-level statements into groups whose cumulative
# line count stays under this cap. Picked to land inside audit-mcp's
# semantic_search per-chunk comfort zone (≤512 token chunks averaging
# ~6 lines each → ~500 chunks per slice, dense enough to embed without
# spilling per-file metadata budgets).
MAX_SLICE_LINES: int = 3000

# Hard ceiling for a single statement that the parser refuses to break
# down further. When one labeled function body (the common shape of
# hermes_dec output) exceeds this, the slice gets a marker telling
# the agent to use read_lines for narrow ranges instead of
# read_function which would dump the whole 12k+ lines.
HARD_SLICE_LINES: int = 12000


# ────────────────────────────────────────────────────────────────────
# Public tool registration
# ────────────────────────────────────────────────────────────────────

def register(mcp: Any) -> None:
    @mcp.tool()
    async def react_native_extract(
        apk_path: str,
        force: bool = False,
    ) -> dict[str, Any]:
        """Extract + decompile + slice the React Native bundles in an APK.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.
            force: Wipe the content-addressed cache before re-extracting.
                Mirrors apktool_decode / jadx_decompile semantics. The
                cache key is the bundle's own SHA256, so a force wipe
                only re-decompiles for the SAME bundle bytes; sibling
                APKs with the same JS bundle still hit the cache.

        Returns:
            Manifest dict with these keys:
              ``decompiled_dir`` — absolute path to the staging dir with
                ``modules/`` + ``slices/`` + ``index.json``. ``None``
                when the APK has no RN bundle (non-RN apps).
              ``bundles_found`` — list of per-bundle metadata
                ``{path, kind, size_bytes, hermes_version|null,
                sha256, status}``. ``status`` is ``ok`` or an error
                string for that bundle (other bundles still process).
              ``js_module_count`` — total file count across modules/ +
                slices/ that audit-mcp will index.
              ``sourcemap_used`` — true when at least one bundle shipped
                a usable ``.map`` file for module-name recovery.
              ``cache_hit`` — true when the cached output was returned
                without re-decompiling.
        """
        target = Path(apk_path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"input not found: {target}")

        # Phase 1 — read bundle bytes out of the APK zipfile. Cheap I/O,
        # safe to run on the event loop directly.
        bundles = _scan_apk_for_bundles(target)
        if not bundles:
            return {
                "decompiled_dir": None,
                "bundles_found": [],
                "js_module_count": 0,
                "sourcemap_used": False,
                "cache_hit": False,
            }

        # Phase 2 — content-addressed cache lookup. Cache key is the
        # combined SHA of every bundle in extraction order so a multi-
        # bundle RAM split gets one shared cache entry.
        combined_hash = hashlib.sha256()
        for b in bundles:
            combined_hash.update(b["sha256"].encode("ascii"))
        cache_key = combined_hash.hexdigest()[:16]
        out_dir = _DEFAULT_WORKDIR / f"rn-{cache_key}"
        manifest_path = out_dir / "index.json"

        if not force and manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["cache_hit"] = True
                return manifest
            except (OSError, json.JSONDecodeError):
                # Corrupt cache — fall through to re-extract.
                pass

        if out_dir.exists():
            await asyncio.to_thread(shutil.rmtree, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "modules").mkdir(exist_ok=True)
        (out_dir / "slices").mkdir(exist_ok=True)

        # Phase 3 — per-bundle decompile + slice. CPU-heavy: thread-pool.
        sourcemap_used = False
        produced_files: list[str] = []
        for b in bundles:
            try:
                bres = await asyncio.to_thread(
                    _decompile_and_slice, b, out_dir,
                )
            except (OSError, RuntimeError, ImportError, ValueError) as exc:
                _log.warning(
                    "rn_extract: bundle %s failed (%s: %s) — skipping",
                    b["path"], type(exc).__name__, str(exc)[:200],
                )
                b["status"] = f"{type(exc).__name__}: {exc}"
                continue
            b["status"] = "ok"
            produced_files.extend(bres["files"])
            if bres["sourcemap_used"]:
                sourcemap_used = True

        # Strip binary fields before JSON serialise. The `bytes` and
        # `sourcemap_bytes` entries are internal-only (used by the
        # decompile + slice phase) and pydantic can't render raw
        # bytecode to JSON. Keep size_bytes + sha256 for traceability.
        for b in bundles:
            if "bytes" in b:
                b["size_bytes"] = len(b.get("bytes") or b"")
                b["bytes"] = None
            if "sourcemap_bytes" in b:
                sm = b.get("sourcemap_bytes")
                b["sourcemap_size_bytes"] = len(sm) if sm else 0
                b["sourcemap_bytes"] = None

        manifest = {
            "decompiled_dir": str(out_dir),
            "bundles_found": bundles,
            "js_module_count": len(produced_files),
            "sourcemap_used": sourcemap_used,
            "cache_hit": False,
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, default=str), encoding="utf-8",
        )
        return manifest


# ────────────────────────────────────────────────────────────────────
# Phase 1 helpers — bundle discovery
# ────────────────────────────────────────────────────────────────────

def _scan_apk_for_bundles(apk_path: Path) -> list[dict[str, Any]]:
    """Walk the APK zip for RN bundle entries + return per-bundle metadata.

    Each returned entry: ``{path, kind, size_bytes, sha256,
    hermes_version, bytes, sourcemap_bytes|None}``. ``bytes`` carries
    the raw bundle content for the decompile phase — keeps the apk file
    handle closed before the slow work starts.
    """
    found: list[dict[str, Any]] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        names = zf.namelist()
        # Walk every bundle-shaped entry. Plain glob matching is enough
        # since RN bundle names are stable.
        candidates: set[str] = set()
        for pattern in _BUNDLE_GLOBS:
            prefix, _, _ = pattern.partition("*")
            for name in names:
                if pattern.startswith("assets/") and not name.startswith("assets/"):
                    continue
                if "*" in pattern:
                    if name.startswith(prefix) and (
                        name.endswith(".bundle")
                        or name.endswith(".hbc")
                        or name.endswith(".jsbundle")
                    ):
                        candidates.add(name)
                else:
                    if name == pattern:
                        candidates.add(name)
        for name in sorted(candidates):
            data = zf.read(name)
            sha = hashlib.sha256(data).hexdigest()
            kind = "hermes" if data[:4] == _HERMES_MAGIC else "plain_js"
            hermes_version: int | None = None
            if kind == "hermes" and len(data) >= 8:
                # Hermes header bytes 4-7 are the bytecode version
                # (little-endian u32). Used to pick the right hermes-dec
                # backend, or to bail when the version is unsupported.
                hermes_version = int.from_bytes(data[4:8], "little")
            sourcemap_bytes: bytes | None = None
            for map_name in (name + ".map", name + ".js.map"):
                if map_name in names:
                    sourcemap_bytes = zf.read(map_name)
                    break
            found.append({
                "path": name,
                "kind": kind,
                "size_bytes": len(data),
                "sha256": sha,
                "hermes_version": hermes_version,
                "bytes": data,
                "sourcemap_bytes": sourcemap_bytes,
            })
    return found


# ────────────────────────────────────────────────────────────────────
# Phase 3 helpers — decompile + slice (runs in thread pool)
# ────────────────────────────────────────────────────────────────────

def _decompile_and_slice(
    bundle: dict[str, Any],
    out_dir: Path,
) -> dict[str, Any]:
    """Decompile one bundle + slice the result into per-file outputs.

    Three steps:
      1. Materialize source text. Hermes → ``hermes_dec.decompile``,
         plain JS → ``jsbeautifier.beautify`` to unminify.
      2. If a sourcemap is present, fan the source out to
         ``modules/<original-path>.js`` so each original module file
         becomes one output file (the gold-standard layout for
         audit-mcp).
      3. If no sourcemap (or modules are still huge), tree-sitter slice
         at top-level declaration boundaries into
         ``slices/slice_NNNN_<first-decl-name>.js``.

    Returns ``{files: [...], sourcemap_used: bool}``.
    """
    source_text: str
    if bundle["kind"] == "hermes":
        source_text = _decompile_hermes(bundle["bytes"])
    else:
        source_text = _beautify_plain_js(bundle["bytes"])

    sourcemap_used = False
    written: list[str] = []

    if bundle["sourcemap_bytes"]:
        try:
            module_files = _split_by_sourcemap(
                source_text, bundle["sourcemap_bytes"], out_dir / "modules",
            )
            written.extend(module_files)
            sourcemap_used = True
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            _log.info(
                "rn_extract: sourcemap for %s unparseable (%s) — "
                "falling back to syntactic slicing",
                bundle["path"], type(exc).__name__,
            )

    if not sourcemap_used:
        slice_files = _slice_syntactic(
            source_text, out_dir / "slices",
            slug=_safe_slug(bundle["path"]),
        )
        written.extend(slice_files)

    return {"files": written, "sourcemap_used": sourcemap_used}


# Process-global lock guarding hermes_dec's stdout-driven decompilation.
# do_decompilation prints output to sys.stdout (process-wide global,
# NOT thread-local). asyncio.to_thread runs each call in a worker
# thread from a shared pool — concurrent extracts would race on the
# redirect. Hermes decompile is CPU-heavy anyway, so serializing it
# per-process is the correct trade.
_HERMES_LOCK_INITIALIZED = False
_HERMES_LOCK = None


def _get_hermes_lock():
    """Lazy-init a threading.Lock without importing threading at module
    load (cuts cold-import cost for processes that never extract RN)."""
    global _HERMES_LOCK_INITIALIZED, _HERMES_LOCK  # noqa: PLW0603
    if not _HERMES_LOCK_INITIALIZED:
        import threading  # noqa: PLC0415
        _HERMES_LOCK = threading.Lock()
        _HERMES_LOCK_INITIALIZED = True
    return _HERMES_LOCK


def _decompile_hermes(bundle_bytes: bytes) -> str:
    """Convert Hermes bytecode → readable JS via the ``hermes_dec`` lib.

    hermes_dec exposes NO ``decompile()`` / ``decompile_string()`` —
    only a CLI entry point that prints to sys.stdout. We call the
    underlying ``do_decompilation(state, file_handle)`` directly + use
    ``contextlib.redirect_stdout`` to capture the output. A
    process-global lock serialises concurrent calls because sys.stdout
    is a shared global across threads.
    """
    try:
        from hermes_dec.decompilation.hbc_decompiler import (  # noqa: PLC0415
            do_decompilation,
        )
        from hermes_dec.decompilation.defs import HermesDecompiler  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "hermes-dec is not installed. Install with "
            "`pip install hermes-dec` to enable React Native Hermes "
            "bundle decompilation.",
        ) from exc

    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    fd, tmp_path = tempfile.mkstemp(suffix=".hbc")
    os.close(fd)
    try:
        Path(tmp_path).write_bytes(bundle_bytes)
        state = HermesDecompiler()
        state.input_file = tmp_path
        state.output_file = None
        buf = io.StringIO()
        lock = _get_hermes_lock()
        with lock, open(tmp_path, "rb") as fh, contextlib.redirect_stdout(buf):
            do_decompilation(state, fh)
        return buf.getvalue()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _beautify_plain_js(bundle_bytes: bytes) -> str:
    """Unminify plain JS bundle via ``jsbeautifier``.

    Minified RN bundles are typically one long line — without beautify
    audit-mcp's tree-sitter slicer sees the whole file as one statement
    and can't carve. After beautify each declaration lands on its own
    line and the slicer can do its job.
    """
    try:
        import jsbeautifier  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "jsbeautifier is not installed. Install with "
            "`pip install jsbeautifier` to enable plain-JS RN bundle "
            "beautification.",
        ) from exc

    raw = bundle_bytes.decode("utf-8", errors="replace")
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.preserve_newlines = True
    opts.max_preserve_newlines = 2
    opts.keep_array_indentation = True
    return jsbeautifier.beautify(raw, opts)


# ────────────────────────────────────────────────────────────────────
# Sourcemap-driven module split (gold path)
# ────────────────────────────────────────────────────────────────────

def _split_by_sourcemap(
    source_text: str,
    sourcemap_bytes: bytes,
    modules_dir: Path,
) -> list[str]:
    """Use the sourcemap's ``sources`` + ``sourcesContent`` arrays to
    write one file per original module.

    React Native's Metro bundler emits sourcemaps with
    ``sourcesContent`` populated when ``--sourcemap-use-absolute-path``
    isn't set. When it IS present we get the original module bodies
    for free — no need to walk the generated bundle.

    Falls back to a ValueError when the map shape is non-standard so
    the caller can switch to syntactic slicing.
    """
    smap = json.loads(sourcemap_bytes)
    sources = smap.get("sources") or []
    contents = smap.get("sourcesContent") or []
    if not sources or not contents or len(sources) != len(contents):
        raise ValueError(
            "sourcemap lacks usable sources + sourcesContent arrays",
        )

    written: list[str] = []
    for original_path, body in zip(sources, contents):
        if body is None:
            continue
        # original_path is webpack/metro-style, like
        # `node_modules/react-native/Libraries/Core/InitializeCore.js`
        # or `__prelude__`. Normalize to a filesystem-safe name.
        safe = _safe_path_inside(modules_dir, original_path)
        safe.parent.mkdir(parents=True, exist_ok=True)
        safe.write_text(body, encoding="utf-8")
        written.append(str(safe))

    if not written:
        raise ValueError("sourcemap yielded zero usable modules")
    return written


def _safe_path_inside(root: Path, requested: str) -> Path:
    """Resolve ``requested`` under ``root``, rejecting any path that
    would escape via ``..`` or absolute references. Mirrors the
    zipfile-extraction safety pattern."""
    # Strip leading slashes + drive letters so absolute-looking
    # sourcemap paths land under root, not at the filesystem root.
    cleaned = requested.lstrip("/\\").replace("\\", "/")
    cleaned = cleaned.replace("../", "_dotdot_/")
    if not cleaned.endswith(".js") and not cleaned.endswith(".jsx"):
        cleaned += ".js"
    candidate = (root / cleaned).resolve()
    if not str(candidate).startswith(str(root.resolve())):
        # Treat as escape attempt — flatten into a generic name.
        return root / "escaped" / cleaned.replace("/", "_")
    return candidate


# ────────────────────────────────────────────────────────────────────
# Tree-sitter syntactic slicer (fallback when no sourcemap)
# ────────────────────────────────────────────────────────────────────

def _slice_syntactic(
    source_text: str,
    slices_dir: Path,
    slug: str,
) -> list[str]:
    """Split ``source_text`` at top-level JS declaration boundaries,
    coalescing adjacent small statements into ~MAX_SLICE_LINES groups.

    Why coalescing matters for hermes_dec output: the decompiler emits
    pseudo-JS that's not strictly valid at module level (label refs
    out of scope, orphan ``}`` from interleaved switch bodies). Tree-
    sitter's error recovery shreds the input into thousands of tiny
    ``expression_statement`` and ``ERROR`` children, one per source
    line. Emitting one slice per child explodes a 24 MB bundle into
    140k+ single-line files which is useless for semantic_search and
    chokes the indexer.

    Strategy:
      1. Walk top-level children once.
      2. Buffer small children; flush when the running line count
         would exceed MAX_SLICE_LINES.
      3. A child bigger than MAX_SLICE_LINES on its own (the
         ``_funN: for(...) switch(...) { ... }`` shape hermes_dec
         emits per Hermes function table entry) flushes the buffer
         and writes a standalone slice. If it exceeds HARD_SLICE_LINES
         we prepend a marker telling the agent to use read_lines.

    Falls back to ``raw_<slug>.js`` (one big file) when tree-sitter
    isn't available or yields zero children, so the rest of the
    pipeline still works without the optional dep.
    """
    try:
        from tree_sitter import Language, Parser  # noqa: PLC0415
        import tree_sitter_javascript as tsjs  # noqa: PLC0415
    except ImportError:
        return _emit_raw_fallback(source_text, slices_dir, slug)

    lang = Language(tsjs.language())
    parser = Parser(lang)
    tree = parser.parse(source_text.encode("utf-8"))

    lines = source_text.splitlines(keepends=True)
    written: list[str] = []
    slice_idx = 0

    # Coalesce buffer: span of contiguous children plus the first
    # few identifiable names for the slice filename hint.
    buf_start: int | None = None
    buf_end: int | None = None
    buf_names: list[str] = []
    _MAX_NAME_HINTS = 3

    def flush_buffer() -> None:
        nonlocal slice_idx, buf_start, buf_end, buf_names
        if buf_start is None or buf_end is None:
            return
        slice_idx += 1
        body = "".join(lines[buf_start:buf_end + 1])
        head = buf_names[0] if buf_names else f"top_{slice_idx}"
        if len(buf_names) > 1:
            head = f"{head}_plus_{len(buf_names) - 1}"
        head_slug = _safe_slug(head)[:60]
        out_path = slices_dir / f"slice_{slice_idx:05d}_{head_slug}.js"
        out_path.write_text(body, encoding="utf-8")
        written.append(str(out_path))
        buf_start = None
        buf_end = None
        buf_names = []

    def emit_standalone(start_line: int, end_line: int, head_name: str) -> None:
        nonlocal slice_idx
        slice_idx += 1
        body = "".join(lines[start_line:end_line + 1])
        line_count = end_line - start_line + 1
        head_slug = _safe_slug(head_name or f"top_{slice_idx}")[:60]
        out_path = slices_dir / f"slice_{slice_idx:05d}_{head_slug}.js"
        if line_count > HARD_SLICE_LINES:
            marker = (
                "// RN_EXTRACT_MARKER: slice exceeds "
                f"{HARD_SLICE_LINES} lines ({line_count}). "
                "Use audit_mcp.read_lines with a narrow range; "
                "read_function on this file returns the whole slice.\n"
            )
            out_path.write_text(marker + body, encoding="utf-8")
        else:
            out_path.write_text(body, encoding="utf-8")
        written.append(str(out_path))

    for child in tree.root_node.children:
        cs = child.start_point[0]
        ce = child.end_point[0]
        child_lines = ce - cs + 1
        head_name = _node_head_name(child, source_text)

        if child_lines >= MAX_SLICE_LINES:
            # Big standalone child — flush buffer then emit on its own.
            flush_buffer()
            emit_standalone(cs, ce, head_name)
            continue

        # Small child — extend buffer or flush + restart when the
        # running span would exceed the budget.
        if buf_start is None:
            buf_start = cs
            buf_end = ce
            if head_name:
                buf_names.append(head_name)
        else:
            projected = ce - buf_start + 1
            if projected > MAX_SLICE_LINES:
                flush_buffer()
                buf_start = cs
                buf_end = ce
                if head_name:
                    buf_names.append(head_name)
            else:
                buf_end = ce
                if head_name and len(buf_names) < _MAX_NAME_HINTS:
                    buf_names.append(head_name)

    flush_buffer()

    if not written:
        return _emit_raw_fallback(source_text, slices_dir, slug)
    return written



def _node_head_name(node: Any, source_text: str) -> str:
    """Extract the most identifying name from a tree-sitter node.

    Handles ``function foo``, ``class Bar``, ``const baz = ...``,
    ``module.exports = ...``, ``something.prototype.x = ...``. Used as
    the slice filename hint so directory listings + audit-mcp's
    semantic search land on something recognizable.
    """
    for child in node.children:
        if child.type == "identifier":
            return source_text[child.start_byte:child.end_byte]
        if child.type in {"variable_declarator", "function_declaration",
                          "class_declaration", "method_definition",
                          "assignment_expression"}:
            for grand in child.children:
                if grand.type == "identifier":
                    return source_text[grand.start_byte:grand.end_byte]
    snippet = source_text[node.start_byte:min(node.end_byte, node.start_byte + 80)]
    return snippet.replace("\n", " ").strip()[:40]


def _emit_raw_fallback(
    source_text: str,
    slices_dir: Path,
    slug: str,
) -> list[str]:
    """Last-resort writer when tree-sitter isn't available OR slicing
    failed entirely. Writes one big file with a marker so the agent
    knows it must use ``read_lines`` to scope its reads."""
    out_path = slices_dir / f"raw_{slug}.js"
    marker = (
        "// RN_EXTRACT_MARKER: this file is the un-sliced raw bundle. "
        "Tree-sitter slicing failed or was unavailable. Use "
        "audit_mcp.read_lines(file_path=<this file>, start=N, end=M) "
        "with a narrow range to scope reads; read_function on this "
        "file returns the whole bundle which exceeds the agent's "
        "context budget.\n"
    )
    out_path.write_text(marker + source_text, encoding="utf-8")
    return [str(out_path)]


def _safe_slug(name: str) -> str:
    """Filesystem-safe slug for slice filenames."""
    keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
    out = "".join(c if c in keep else "_" for c in name)
    return out.strip("._") or "anon"
