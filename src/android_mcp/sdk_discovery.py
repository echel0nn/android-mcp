"""Android SDK build-tools binary discovery — cross-platform fallback.

The Android SDK ships a handful of binaries (``apksigner``, ``aapt``,
``aapt2``, ``zipalign``, ``d8``) under
``<sdk>/build-tools/<version>/``. None of the official installers add
that directory to PATH on any OS, so ``shutil.which`` alone misses
them on a fresh box:

  - **Windows / Android Studio**: installs into
    ``%LOCALAPPDATA%\\Android\\Sdk\\`` but never touches user PATH.
  - **macOS / Android Studio**: ``~/Library/Android/sdk/``, same gap.
  - **Linux / Android Studio**: ``~/Android/Sdk/``, same gap.
  - **Linux / package manager**: distro paths (Arch
    ``/opt/android-sdk``, NixOS via ``ANDROID_SDK_ROOT``).
  - **CI / Docker**: usually exports ``ANDROID_SDK_ROOT`` or
    ``ANDROID_HOME`` but does NOT add ``build-tools/<ver>`` to PATH
    because the SDK ships dozens of versioned dirs.

This module returns the resolved path or ``None``, picking the
highest-semver build-tools version when several are installed.
Resolution is cached for the process lifetime — the SDK does not
move once the worker starts.

Resolution order (first hit wins):

  1. ``shutil.which(tool_name)`` — explicit user PATH wins, lets
     the operator override discovery by adding a specific version to
     PATH manually.
  2. ``$ANDROID_SDK_ROOT/build-tools/<highest-semver>/<tool>``
     (canonical env var since Android Studio Arctic Fox / 2021).
  3. ``$ANDROID_HOME/build-tools/<highest-semver>/<tool>`` (legacy
     alias, still widely used in CI scripts and Dockerfiles).
  4. Per-OS Android Studio defaults:
     - Windows: ``%LOCALAPPDATA%\\Android\\Sdk\\``
     - macOS:   ``~/Library/Android/sdk/``
     - Linux:   ``~/Android/Sdk/``
  5. Per-OS package-manager defaults:
     - macOS Homebrew: ``/usr/local/share/android-sdk`` (Intel),
       ``/opt/homebrew/share/android-sdk`` (Apple Silicon).
     - Linux distros: ``/opt/android-sdk``, ``/opt/android-sdk-linux``,
       ``/usr/lib/android-sdk``.

Binary extension is OS-conditioned: Windows tries ``<tool>.bat`` then
``<tool>.exe`` then bare ``<tool>``; POSIX tries bare ``<tool>`` only.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Final

_log = logging.getLogger(__name__)

# Per-process resolution cache. SDK doesn't move during runtime, so a
# successful resolution stays valid; a miss is also cached because the
# negative path (full filesystem walk) is the expensive case and
# repeated invocations of the same tool within a process should be
# cheap. Cache key is the tool name; value is the resolved path or
# None for a known-missing tool.
_CACHE: dict[str, str | None] = {}


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _candidate_extensions() -> tuple[str, ...]:
    """Extensions tried for a tool name on the current OS.

    Windows SDK ships .bat wrappers around the JAR for most tools and
    .exe for native ones (aapt, aapt2). POSIX ships bare scripts.
    Empty string ``""`` covers the no-extension case last so a
    plain Linux-style symlink without an extension still resolves on
    Windows boxes where the user manually placed one.
    """
    if _is_windows():
        return (".bat", ".exe", "")
    return ("",)


def _semver_key(name: str) -> tuple[int, ...]:
    """Sort key for build-tools dir names like ``34.0.0`` or ``android-13``.

    Returns a tuple of ints — directories that don't parse fall back
    to ``(-1,)`` so they sort last and never win against a real
    version. Sort order is descending in callers (largest semver
    wins) — ``34.0.0`` > ``33.0.2`` > ``30.0.3``.
    """
    parts = re.findall(r"\d+", name)
    if not parts:
        return (-1,)
    return tuple(int(p) for p in parts)


def _sdk_root_candidates() -> list[Path]:
    """Build the ordered list of SDK root directories to probe.

    Ordering matters: env vars come first (operator-explicit), then
    per-OS Android Studio defaults, then per-OS package-manager
    defaults. Each path is normalized and de-duplicated so the same
    SDK installed once never gets probed twice (matters when
    ``ANDROID_HOME`` and ``ANDROID_SDK_ROOT`` both point at the same
    dir — common in CI).
    """
    home = Path.home()
    candidates: list[Path] = []

    for env_var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        raw = os.environ.get(env_var)
        if raw:
            candidates.append(Path(raw))

    if _is_windows():
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            candidates.append(Path(local_appdata) / "Android" / "Sdk")
        # Also probe ProgramFiles for system-wide installs (rare but
        # happens on locked-down corporate boxes).
        program_files = os.environ.get("ProgramFiles")
        if program_files:
            candidates.append(Path(program_files) / "Android" / "android-sdk")
    elif _is_macos():
        candidates.append(home / "Library" / "Android" / "sdk")
        # Homebrew cask install paths.
        candidates.append(Path("/usr/local/share/android-sdk"))
        candidates.append(Path("/opt/homebrew/share/android-sdk"))
        candidates.append(Path("/usr/local/lib/android/sdk"))
    else:
        # Linux + other POSIX.
        candidates.append(home / "Android" / "Sdk")
        candidates.append(Path("/opt/android-sdk"))
        candidates.append(Path("/opt/android-sdk-linux"))
        candidates.append(Path("/usr/lib/android-sdk"))
        candidates.append(Path("/usr/local/lib/android/sdk"))

    # De-duplicate while preserving order. ``Path`` equality handles
    # different string spellings of the same absolute path (e.g.
    # ``/Users/x/Library/Android/sdk`` vs the same with a trailing slash).
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in candidates:
        try:
            resolved = p.resolve(strict=False)
        except (OSError, RuntimeError):
            resolved = p
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(p)
    return unique


def _highest_build_tools_dir(sdk_root: Path) -> Path | None:
    """Return ``<sdk_root>/build-tools/<highest-semver>`` or None.

    The build-tools subdir contains one folder per installed version
    (e.g. ``30.0.3``, ``33.0.2``, ``34.0.0``). Picks the largest
    semver dir so newer signing schemes (v3.1, v4) parse correctly.
    Returns None when the SDK exists but build-tools is empty or
    absent (a SDK install without build-tools is incomplete — the
    operator must run ``sdkmanager 'build-tools;<ver>'`` once).
    """
    build_tools_root = sdk_root / "build-tools"
    try:
        if not build_tools_root.is_dir():
            return None
        versions = [p for p in build_tools_root.iterdir() if p.is_dir()]
    except OSError:
        return None
    if not versions:
        return None
    versions.sort(key=lambda p: _semver_key(p.name), reverse=True)
    return versions[0]


def find_android_sdk_tool(tool_name: str) -> str | None:
    """Resolve an Android SDK build-tools binary path.

    Returns the absolute path to an executable file, or ``None`` when
    no SDK install on the box contains the requested tool. Result is
    cached per-process — the SDK location does not change during a
    worker's lifetime, and resolution involves multiple stat calls
    that should not repeat on every tool invocation.

    Args:
        tool_name: Bare tool name without extension (``"apksigner"``,
            ``"aapt"``, ``"aapt2"``, ``"zipalign"``, ``"d8"``).
    """
    if tool_name in _CACHE:
        return _CACHE[tool_name]

    # 1. Explicit PATH wins — lets the operator manually override
    # discovery by symlinking or adding a specific version to PATH.
    hit = shutil.which(tool_name)
    if hit is not None:
        _CACHE[tool_name] = hit
        return hit

    # 2-5. Probe each SDK root candidate in order, picking the highest
    # build-tools version per SDK. First SDK that contains the tool
    # wins — we don't merge across SDKs because mixing versions across
    # installs is a footgun (different signing scheme parser
    # behavior).
    extensions: Final[tuple[str, ...]] = _candidate_extensions()
    for sdk_root in _sdk_root_candidates():
        build_tools_dir = _highest_build_tools_dir(sdk_root)
        if build_tools_dir is None:
            continue
        for ext in extensions:
            candidate = build_tools_dir / f"{tool_name}{ext}"
            try:
                if candidate.is_file():
                    resolved = str(candidate)
                    _log.info(
                        "android-mcp: resolved %r at %s "
                        "(sdk_root=%s, build_tools=%s)",
                        tool_name, resolved, sdk_root, build_tools_dir.name,
                    )
                    _CACHE[tool_name] = resolved
                    return resolved
            except OSError:
                continue

    _CACHE[tool_name] = None
    return None


def clear_cache() -> None:
    """Drop the per-process resolution cache.

    Useful in tests; not called by production code. Production
    workers are expected to never see SDK installs appear or
    disappear during their lifetime.
    """
    _CACHE.clear()
