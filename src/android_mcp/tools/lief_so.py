"""LIEF wrapper — analyze native shared objects inside APKs.

Android APKs ship native code as ELF shared objects under
`lib/<abi>/*.so` (where abi is one of arm64-v8a, armeabi-v7a, x86,
x86_64, and a few historical others). These libraries do crypto,
video decoding, anti-debug, and other work that the dex bytecode
delegates out to. They are the part of the APK that escapes the JVM
sandbox — every audit pass needs to know what mitigations they
carry.

The wrapper opens the APK as a zip, extracts every recognised native
library to a temp dir, parses each with LIEF, and reports structural
facts plus a hardening summary. Missing mitigations (no NX, no PIE,
no RELRO, no stack canary, not stripped) are the audit hooks — they
tell a reviewer where the native attack surface skipped the standard
exploit-mitigation toolbox.

`lief>=0.16.0` lives in `[project] dependencies`, so this tool needs
no extra install step beyond a normal `pip install -e .`. LIEF itself
is imported lazily inside the per-file summary helper, keeping
import-time cost zero for callers that never hit this tool.
"""

from __future__ import annotations

import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# ABIs Android ships native code under. Files outside these abi
# subdirectories are user resources, not loadable libraries, and
# stay out of the analysis surface.
_KNOWN_ABIS = frozenset(
    {
        "arm64-v8a",
        "armeabi-v7a",
        "armeabi",
        "x86",
        "x86_64",
        "mips",
        "mips64",
        "riscv64",
    }
)

# Cap on exported-symbol names returned per library. A library that
# exports thousands of symbols is framework code (libc, OpenSSL,
# Skia); the reviewer does not need every name dumped at once.
_EXPORTED_SYMBOL_CAP = 200

# DT_FLAGS bit for "resolve all symbols at load time". When set, RELRO
# is "full" rather than just "partial". See `man elf`.
_DF_BIND_NOW = 0x8

# Segment flag bit for "executable". When the GNU_STACK segment has
# this bit unset, the loader marks the stack non-executable (NX).
_PF_X = 0x1

# Names the C runtime emits when `-fstack-protector` was used at
# compile time. Presence in imports/symbols is a proxy for
# stack-canary protection.
_STACK_CANARY_SYMBOLS = frozenset({"__stack_chk_fail", "__stack_chk_guard"})


def register(mcp: Any) -> None:
    @mcp.tool()
    async def analyze_native_libs(apk_path: str) -> list[dict[str, Any]]:
        """Walk every `lib/<abi>/*.so` inside an APK and return LIEF's
        structural summary for each.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.

        Returns:
            List of dicts, one per shared object. Each dict has
            `abi`, `name`, `header`, `imports`, `exports`,
            `relocations`, and `hardening: {nx, pie, relro, canary,
            stripped}`. Parse failures on individual libraries
            surface as `{"abi", "name", "error": "..."}` entries; the
            call does not abort on the first bad library.

            APKs with no native code return an empty list.
        """
        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        try:
            zf = zipfile.ZipFile(apk)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"not a valid zip/apk: {apk} ({exc})") from exc

        results: list[dict[str, Any]] = []
        with zf:
            so_entries = [info for info in zf.infolist() if _is_native_lib_entry(info.filename)]
            if not so_entries:
                return []

            with tempfile.TemporaryDirectory(prefix="android-mcp-lief-") as tmp:
                tmp_dir = Path(tmp)
                for info in so_entries:
                    # info.filename is like "lib/arm64-v8a/libfoo.so".
                    parts = info.filename.split("/")
                    abi = parts[1] if len(parts) >= 3 else "unknown"
                    so_name = parts[-1]

                    out_path = tmp_dir / f"{abi}__{so_name}"
                    try:
                        with zf.open(info) as src, out_path.open("wb") as dst:
                            dst.write(src.read())
                    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
                        results.append(
                            {
                                "abi": abi,
                                "name": so_name,
                                "error": f"extract failed: {type(exc).__name__}: {exc}",
                            }
                        )
                        continue

                    results.append(_summarize_elf(abi, so_name, out_path))

        return results


def _is_native_lib_entry(name: str) -> bool:
    """True iff `name` looks like `lib/<known-abi>/<something>.so`."""
    if not name.endswith(".so"):
        return False
    parts = name.split("/")
    if len(parts) != 3:
        # Disallow nested paths like `lib/arm64-v8a/sub/libfoo.so` —
        # Android's loader only looks one level deep.
        return False
    if parts[0] != "lib":
        return False
    return parts[1] in _KNOWN_ABIS


def _summarize_elf(abi: str, name: str, path: Path) -> dict[str, Any]:
    """Parse one .so with LIEF and return its structural summary.

    LIEF is imported lazily inside this function so callers that never
    hit a `.so` (most empty / pure-Java APKs) pay zero LIEF
    import-time cost.
    """
    import lief

    try:
        binary = lief.parse(str(path))
    except (RuntimeError, OSError) as exc:
        return {
            "abi": abi,
            "name": name,
            "error": f"lief.parse raised: {type(exc).__name__}: {exc}",
        }

    if binary is None:
        return {
            "abi": abi,
            "name": name,
            "error": "lief.parse returned None (not a parseable ELF)",
        }

    return {
        "abi": abi,
        "name": name,
        "header": _summarize_header(binary),
        "imports": _summarize_imports(binary),
        "exports": _summarize_exports(binary),
        "relocations": _count_relocations(binary),
        "hardening": _summarize_hardening(binary),
    }


def _summarize_header(binary: Any) -> dict[str, Any]:
    """Pull the smallest header summary the reviewer can act on."""
    h = binary.header
    return {
        "type": _enum_name(h.file_type),
        "machine": _enum_name(h.machine_type),
        "entrypoint": int(h.entrypoint),
        "identity_class": _enum_name(h.identity_class),
    }


def _summarize_imports(binary: Any) -> list[str]:
    """Imported library names (DT_NEEDED entries)."""
    try:
        return list(binary.libraries)
    except (AttributeError, RuntimeError):
        return []


def _summarize_exports(binary: Any) -> list[str]:
    """Exported symbol names, capped at `_EXPORTED_SYMBOL_CAP`."""
    out: list[str] = []
    try:
        for sym in binary.exported_symbols:
            sym_name = getattr(sym, "name", None)
            if sym_name:
                out.append(sym_name)
            if len(out) >= _EXPORTED_SYMBOL_CAP:
                break
    except (AttributeError, RuntimeError):
        return out
    return out


def _count_relocations(binary: Any) -> int:
    """Number of relocation entries. Returning the full list would
    blow the token budget on any non-trivial .so."""
    try:
        return len(list(binary.relocations))
    except (AttributeError, RuntimeError, TypeError):
        return 0


def _summarize_hardening(binary: Any) -> dict[str, Any]:
    """Detect standard ELF exploit-mitigation flags.

    See https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
    for the RELRO state machine, and https://github.com/slimm609/checksec
    for the canonical reference implementation.
    """
    return {
        "nx": _has_nx(binary),
        "pie": _is_pie(binary),
        "relro": _relro_state(binary),
        "canary": _has_stack_canary(binary),
        "stripped": _is_stripped(binary),
    }


def _has_nx(binary: Any) -> bool:
    """GNU_STACK segment present without the execute bit => NX on.

    Absent GNU_STACK historically meant "executable stack by default";
    we report that as NX off so the reviewer can flag the library.
    """
    try:
        for seg in binary.segments:
            if _enum_name(seg.type) == "GNU_STACK":
                return (int(seg.flags) & _PF_X) == 0
    except (AttributeError, RuntimeError):
        return False
    return False


def _is_pie(binary: Any) -> bool:
    """For a shared object (`.so`), file type is always DYN; the file
    is position-independent by construction. Report True for any DYN
    ELF so the reviewer sees a uniform "PIE = yes" across libraries
    and a clear "no" for the rare case of a static executable wedged
    into the APK by mistake."""
    try:
        return _enum_name(binary.header.file_type) == "DYN"
    except (AttributeError, RuntimeError):
        return False


def _relro_state(binary: Any) -> str:
    """Return one of `"full"`, `"partial"`, `"none"`.

    `partial` = `PT_GNU_RELRO` segment present.
    `full`    = `PT_GNU_RELRO` plus `DT_BIND_NOW` or `DT_FLAGS & DF_BIND_NOW`.
    """
    has_relro = False
    has_bind_now = False
    try:
        for seg in binary.segments:
            if _enum_name(seg.type) == "GNU_RELRO":
                has_relro = True
                break
        for entry in getattr(binary, "dynamic_entries", []):
            tag = _enum_name(getattr(entry, "tag", ""))
            if tag == "BIND_NOW":
                has_bind_now = True
                break
            if tag == "FLAGS":
                value = int(getattr(entry, "value", 0))
                if value & _DF_BIND_NOW:
                    has_bind_now = True
                    break
    except (AttributeError, RuntimeError):
        return "none"

    if has_relro and has_bind_now:
        return "full"
    if has_relro:
        return "partial"
    return "none"


def _has_stack_canary(binary: Any) -> bool:
    """True iff `__stack_chk_fail` or `__stack_chk_guard` appears in
    imports or the symbol table — proxy for `-fstack-protector` at
    compile time."""
    try:
        for sym in getattr(binary, "imported_symbols", []) or []:
            if getattr(sym, "name", "") in _STACK_CANARY_SYMBOLS:
                return True
        for sym in getattr(binary, "symbols", []) or []:
            if getattr(sym, "name", "") in _STACK_CANARY_SYMBOLS:
                return True
    except (AttributeError, RuntimeError):
        return False
    return False


def _is_stripped(binary: Any) -> bool:
    """A library is stripped iff it has no `.symtab` section.

    `.dynsym` (always present in a shared object) only covers exported
    symbols and is not what `strip(1)` removes. `.symtab` is the
    developer-side debug symbol table; its absence is the strip
    signal.
    """
    try:
        for section in binary.sections:
            if section.name == ".symtab":
                return False
    except (AttributeError, RuntimeError):
        return False
    return True


def _enum_name(value: Any) -> str:
    """Return the trailing name of an enum-ish LIEF value.

    LIEF enums repr as `<ENUMCLASS.NAME: int>` or stringify to
    `ENUMCLASS.NAME`. Both cases are handled by taking the substring
    after the final dot. Plain strings and unknown types pass through.
    """
    text = str(value)
    return text.rsplit(".", 1)[-1].split(":", 1)[0].strip()
