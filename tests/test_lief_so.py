"""Tests for the LIEF wrapper — analyze native libs inside APKs.

The empty/no-so/non-apk paths run without LIEF installed (LIEF is
imported lazily inside `_summarize_elf`, never reached when no
`lib/<abi>/*.so` entry is found). Tests that DO exercise LIEF are
gated on `pytest.importorskip("lief")` so a developer machine
without the optional C++ extension still gets a clean run.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest


def _make_apk(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    """Build a tiny zip-file APK with the named entries."""
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return apk


async def _call_analyze(apk_path: str) -> list[dict[str, Any]]:
    """Resolve the registered `analyze_native_libs` handler and call it.

    Mirrors the pattern other android-mcp tools follow: `register` is
    the public entrypoint, so the test reaches the handler through it
    rather than poking at the module-private function.
    """
    from android_mcp.tools.lief_so import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture analyze_native_libs"
    return await fn(apk_path=apk_path)


async def test_empty_apk_returns_empty_list(tmp_path: Path) -> None:
    apk = _make_apk(tmp_path, {"AndroidManifest.xml": b"<manifest/>"})
    result = await _call_analyze(str(apk))
    assert result == []


async def test_non_so_files_in_lib_skipped(tmp_path: Path) -> None:
    """Files inside lib/<abi>/ that are not `.so` are not native code."""
    apk = _make_apk(
        tmp_path,
        {
            "lib/arm64-v8a/README.txt": b"hello",
            "lib/x86_64/notes.md": b"# hi",
        },
    )
    result = await _call_analyze(str(apk))
    assert result == []


async def test_so_in_unknown_abi_skipped(tmp_path: Path) -> None:
    """`.so` files outside a known ABI directory are not real native libs."""
    apk = _make_apk(
        tmp_path,
        {
            "lib/unknown-abi/libfoo.so": b"junk",
            "assets/lib/arm64/libnested.so": b"junk",
        },
    )
    result = await _call_analyze(str(apk))
    assert result == []


async def test_nested_so_under_abi_skipped(tmp_path: Path) -> None:
    """The Android loader looks one level deep under `lib/<abi>/`."""
    apk = _make_apk(
        tmp_path,
        {
            "lib/arm64-v8a/sub/libfoo.so": b"junk",
        },
    )
    result = await _call_analyze(str(apk))
    assert result == []


async def test_missing_apk_raises_filenotfound(tmp_path: Path) -> None:
    nonexistent = tmp_path / "missing.apk"
    with pytest.raises(FileNotFoundError):
        await _call_analyze(str(nonexistent))


async def test_non_apk_file_raises_value_error(tmp_path: Path) -> None:
    not_apk = tmp_path / "notes.txt"
    not_apk.write_text("not a zip at all")
    with pytest.raises(ValueError, match="not a valid zip"):
        await _call_analyze(str(not_apk))


async def test_directory_raises_value_error(tmp_path: Path) -> None:
    a_dir = tmp_path / "looks-like-apk"
    a_dir.mkdir()
    with pytest.raises(ValueError, match="not a file"):
        await _call_analyze(str(a_dir))


async def test_malformed_so_handled_gracefully(tmp_path: Path) -> None:
    """A file named `.so` but containing non-ELF bytes surfaces as
    one error-shaped entry, not a raised exception."""
    pytest.importorskip("lief")
    apk = _make_apk(
        tmp_path,
        {"lib/arm64-v8a/libgarbage.so": b"not really an ELF file"},
    )
    result = await _call_analyze(str(apk))
    assert len(result) == 1
    entry = result[0]
    assert entry["abi"] == "arm64-v8a"
    assert entry["name"] == "libgarbage.so"
    assert "error" in entry, f"expected error key on malformed .so, got {entry}"


async def test_multiple_abis_each_surface(tmp_path: Path) -> None:
    """A multi-arch APK with garbage bytes yields one entry per ABI,
    each carrying the per-library error shape rather than raising."""
    pytest.importorskip("lief")
    apk = _make_apk(
        tmp_path,
        {
            "lib/arm64-v8a/libfoo.so": b"garbage-arm64",
            "lib/x86_64/libfoo.so": b"garbage-x86",
        },
    )
    result = await _call_analyze(str(apk))
    abis = sorted(entry["abi"] for entry in result)
    assert abis == ["arm64-v8a", "x86_64"]
    for entry in result:
        assert entry["name"] == "libfoo.so"
        assert "error" in entry


def test_is_native_lib_entry_classifier() -> None:
    """Exercise the gatekeeper that decides which zip entries reach LIEF."""
    from android_mcp.tools.lief_so import _is_native_lib_entry

    # positive cases — known ABIs, exactly one path segment under lib/<abi>/
    assert _is_native_lib_entry("lib/arm64-v8a/libfoo.so")
    assert _is_native_lib_entry("lib/x86_64/libcrypto.so")
    assert _is_native_lib_entry("lib/armeabi-v7a/libssl.so")
    assert _is_native_lib_entry("lib/armeabi/libold.so")
    assert _is_native_lib_entry("lib/x86/libi386.so")
    assert _is_native_lib_entry("lib/riscv64/libriscv.so")

    # negative cases
    assert not _is_native_lib_entry("AndroidManifest.xml")
    assert not _is_native_lib_entry("assets/lib/arm64/libfoo.so")  # wrong prefix
    assert not _is_native_lib_entry("lib/unknown-abi/libfoo.so")  # unknown abi
    assert not _is_native_lib_entry("lib/arm64-v8a/README.txt")  # not .so
    assert not _is_native_lib_entry("lib/libfoo.so")  # no abi component
    assert not _is_native_lib_entry("lib/arm64-v8a/sub/libfoo.so")  # too deep


def test_enum_name_strips_class_prefix() -> None:
    """The enum_name helper has to tolerate both LIEF's repr formats."""
    from android_mcp.tools.lief_so import _enum_name

    # LIEF enums repr as `<ENUMCLASS.NAME: 7>` or stringify to `ENUMCLASS.NAME`.
    assert _enum_name("FileType.DYN") == "DYN"
    assert _enum_name("<FileType.DYN: 3>") == "DYN"
    assert _enum_name("DYN") == "DYN"
    # Plain values pass through unchanged after trimming.
    assert _enum_name(42) == "42"
