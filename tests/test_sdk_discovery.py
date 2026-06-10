"""Tests for cross-platform Android SDK build-tools discovery.

Covers the five-tier resolution order, OS-conditioned extension
handling, multi-version semver sort, env-var precedence, and the
all-missing fallback. Filesystem fixtures live under a tmp_path to
keep tests hermetic; no real Android SDK on the test box is required.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from android_mcp import sdk_discovery


@pytest.fixture(autouse=True)
def _clear_cache():
    sdk_discovery.clear_cache()
    yield
    sdk_discovery.clear_cache()


@pytest.fixture
def _clean_env(monkeypatch):
    """Strip every env var the resolver reads so each test sets its own."""
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME", "LOCALAPPDATA", "ProgramFiles"):
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


def _make_sdk(root: Path, versions: list[str], tool: str, ext: str = "") -> None:
    """Create a fake SDK install with the given build-tools versions."""
    for v in versions:
        version_dir = root / "build-tools" / v
        version_dir.mkdir(parents=True, exist_ok=True)
        bin_path = version_dir / f"{tool}{ext}"
        bin_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        if not ext:
            try:
                bin_path.chmod(0o755)
            except (OSError, NotImplementedError):
                pass  # Windows: chmod is a no-op on non-NTFS-ACL filesystems


# ── Resolution order ────────────────────────────────────────────────


def test_explicit_path_wins_over_sdk_root(tmp_path, _clean_env):
    """A shutil.which hit short-circuits the SDK probe even if both exist."""
    fake_path_dir = tmp_path / "path_dir"
    fake_path_dir.mkdir()
    path_apksigner = fake_path_dir / "apksigner"
    path_apksigner.write_text("# from PATH", encoding="utf-8")

    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=str(path_apksigner)):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result == str(path_apksigner)


def test_android_sdk_root_resolves_when_path_missing(tmp_path, _clean_env):
    """ANDROID_SDK_ROOT is tier 2 — used when shutil.which returns None."""
    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "34.0.0" in result
    assert result.endswith("apksigner") or result.endswith("apksigner.bat") or result.endswith("apksigner.exe")


def test_android_home_resolves_when_sdk_root_unset(tmp_path, _clean_env):
    """ANDROID_HOME (tier 3) is used when ANDROID_SDK_ROOT is unset."""
    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["33.0.2"], "apksigner")
    _clean_env.setenv("ANDROID_HOME", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "33.0.2" in result


def test_sdk_root_takes_precedence_over_home(tmp_path, _clean_env):
    """When both env vars point at distinct SDKs, ANDROID_SDK_ROOT wins."""
    sdk_root = tmp_path / "sdk_root"
    sdk_home = tmp_path / "sdk_home"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    _make_sdk(sdk_home, ["30.0.3"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))
    _clean_env.setenv("ANDROID_HOME", str(sdk_home))

    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "sdk_root" in result.replace("\\", "/")


# ── Multi-version semver sort ───────────────────────────────────────


def test_highest_semver_wins(tmp_path, _clean_env):
    """When multiple build-tools versions exist, the highest semver wins."""
    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["30.0.3", "33.0.2", "34.0.0", "29.0.2"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "34.0.0" in result
    assert "33.0.2" not in result
    assert "30.0.3" not in result


def test_non_semver_dir_does_not_win_against_real_version(tmp_path, _clean_env):
    """Garbage subdirs in build-tools (e.g. ``.tmp_install``) sort last."""
    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["34.0.0", "foo-bar"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "34.0.0" in result


# ── Per-OS defaults ────────────────────────────────────────────────


def test_per_os_default_windows(tmp_path, _clean_env, monkeypatch):
    """On Windows, %LOCALAPPDATA%\\Android\\Sdk is the default install."""
    sdk_root = tmp_path / "Android" / "Sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner", ext=".bat")
    _clean_env.setenv("LOCALAPPDATA", str(tmp_path))

    monkeypatch.setattr(sdk_discovery, "_is_windows", lambda: True)
    monkeypatch.setattr(sdk_discovery, "_is_macos", lambda: False)
    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert result.endswith("apksigner.bat")


def test_per_os_default_macos(tmp_path, _clean_env, monkeypatch):
    """On macOS, ~/Library/Android/sdk is the default install."""
    sdk_root = tmp_path / "Library" / "Android" / "sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    monkeypatch.setattr(sdk_discovery, "_is_windows", lambda: False)
    monkeypatch.setattr(sdk_discovery, "_is_macos", lambda: True)
    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "Library/Android/sdk" in result.replace("\\", "/")


def test_per_os_default_linux(tmp_path, _clean_env, monkeypatch):
    """On Linux, ~/Android/Sdk is the default install."""
    sdk_root = tmp_path / "Android" / "Sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    monkeypatch.setattr(sdk_discovery, "_is_windows", lambda: False)
    monkeypatch.setattr(sdk_discovery, "_is_macos", lambda: False)
    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")

    assert result is not None
    assert "Android/Sdk" in result.replace("\\", "/")


# ── Negative paths ─────────────────────────────────────────────────


def test_returns_none_when_no_sdk_anywhere(tmp_path, _clean_env, monkeypatch):
    """No SDK in env + no per-OS default + no PATH → returns None cleanly."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "nohome"))
    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")
    assert result is None


def test_sdk_without_build_tools_dir_is_skipped(tmp_path, _clean_env):
    """An SDK env var pointing at a dir with no build-tools subdir is skipped."""
    sdk_root = tmp_path / "empty_sdk"
    sdk_root.mkdir()
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))
    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")
    assert result is None


def test_build_tools_dir_with_no_versions_is_skipped(tmp_path, _clean_env):
    """A build-tools dir exists but contains no versioned subdirs → None."""
    sdk_root = tmp_path / "sdk"
    (sdk_root / "build-tools").mkdir(parents=True)
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))
    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        result = sdk_discovery.find_android_sdk_tool("apksigner")
    assert result is None


# ── Caching ─────────────────────────────────────────────────────────


def test_resolution_is_cached_per_process(tmp_path, _clean_env):
    """Second call hits the cache, not the filesystem walker."""
    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None) as mock_which:
        first = sdk_discovery.find_android_sdk_tool("apksigner")
        second = sdk_discovery.find_android_sdk_tool("apksigner")

    assert first == second
    # shutil.which should be called exactly once across both invocations.
    assert mock_which.call_count == 1


def test_negative_result_is_also_cached(_clean_env, tmp_path, monkeypatch):
    """A missing-SDK result is cached so we don't re-walk the FS."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "nohome"))
    with patch.object(sdk_discovery.shutil, "which", return_value=None) as mock_which:
        first = sdk_discovery.find_android_sdk_tool("apksigner")
        second = sdk_discovery.find_android_sdk_tool("apksigner")

    assert first is None
    assert second is None
    assert mock_which.call_count == 1


def test_clear_cache_forces_reprobe(tmp_path, _clean_env):
    """clear_cache() invalidates the cache so the next call re-walks."""
    sdk_root = tmp_path / "sdk"
    _make_sdk(sdk_root, ["34.0.0"], "apksigner")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None) as mock_which:
        sdk_discovery.find_android_sdk_tool("apksigner")
        sdk_discovery.clear_cache()
        sdk_discovery.find_android_sdk_tool("apksigner")

    assert mock_which.call_count == 2


# ── Multi-tool isolation ────────────────────────────────────────────


def test_different_tools_resolve_independently(tmp_path, _clean_env):
    """apksigner and aapt are cached under separate keys."""
    sdk_root = tmp_path / "sdk"
    version_dir = sdk_root / "build-tools" / "34.0.0"
    version_dir.mkdir(parents=True)
    (version_dir / "apksigner").write_text("apksigner_body", encoding="utf-8")
    (version_dir / "aapt").write_text("aapt_body", encoding="utf-8")
    _clean_env.setenv("ANDROID_SDK_ROOT", str(sdk_root))

    with patch.object(sdk_discovery.shutil, "which", return_value=None):
        apksigner_path = sdk_discovery.find_android_sdk_tool("apksigner")
        aapt_path = sdk_discovery.find_android_sdk_tool("aapt")

    assert apksigner_path is not None
    assert aapt_path is not None
    assert apksigner_path != aapt_path
    assert apksigner_path.endswith("apksigner")
    assert aapt_path.endswith("aapt")
