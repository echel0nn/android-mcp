"""apktool wrapper — extract resources and smali from an APK.

apktool is the canonical reverse-engineering decoder for Android APKs.
It rebuilds the AndroidManifest.xml from the binary XML, decodes the
resource table, disassembles dex to smali, and rebuilds the APK after
edits. The wrapper exposes a one-shot decode operation; rebuild is a
follow-up tool we add when the operator's flow needs it.

OS prerequisite: `apktool` on PATH. Install via package manager or
download the JAR from https://apktool.org/ and put a launcher script on
PATH that does `java -jar /path/to/apktool.jar "$@"`.

Output: every artifact lands under `<workdir>/apktool-<sha256>/`.
Predictable layout keeps follow-up tools (jadx, mobsf, androguard,
custom yara) able to find what apktool produced.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Apktool's default workspace lives at ~/.android-mcp/work/. Operator
# overrides via ANDROID_MCP_WORKDIR env var on the server.
_DEFAULT_WORKDIR = Path(os.environ.get("ANDROID_MCP_WORKDIR", "~/.android-mcp/work")).expanduser()


def register(mcp: Any) -> None:
    @mcp.tool()
    async def apktool_decode(
        apk_path: str,
        force: bool = False,
        no_resources: bool = False,
        no_sources: bool = False,
    ) -> dict[str, Any]:
        """Decode an APK with apktool.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.
            force: Pass --force to apktool (overwrite existing output dir).
            no_resources: Pass --no-res (skip resource decoding; faster).
            no_sources: Pass --no-src (skip smali; manifest + resources only).

        Returns:
            dict with `output_dir`, `apk_sha256`, `manifest_path`,
            `smali_dirs` (list), `assets_dir`, `res_dir`, `elapsed_s`.
            Errors raise; the HTTP layer surfaces them as 500.
        """
        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        sha = _sha256_file(apk)
        out_dir = _DEFAULT_WORKDIR / f"apktool-{sha[:16]}"
        out_dir.parent.mkdir(parents=True, exist_ok=True)

        # Resolve `apktool` via shutil.which so we walk PATHEXT on Windows
        # (where scoop / chocolatey install the launcher as `apktool.CMD`).
        # Python's subprocess on Windows does NOT auto-append PATHEXT when
        # shell=False, so a bare ["apktool", ...] raises FileNotFoundError
        # even when the .CMD shim is on PATH and `where.exe apktool` finds it.
        apktool_bin = shutil.which("apktool")
        if apktool_bin is None:
            raise FileNotFoundError(
                "apktool not found on PATH. Install via "
                "`scoop install apktool` (Windows), `brew install apktool` "
                "(macOS), or your distro package manager; alternatively "
                "download the JAR from https://apktool.org/ and put a "
                "launcher script on PATH.",
            )
        cmd = [apktool_bin, "d", str(apk), "-o", str(out_dir)]
        if force:
            cmd.append("--force")
        if no_resources:
            cmd.append("--no-res")
        if no_sources:
            cmd.append("--no-src")

        loop = asyncio.get_event_loop()
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=600),  # noqa: S603
        )

        if proc.returncode != 0:
            raise RuntimeError(
                f"apktool failed (exit {proc.returncode}): "
                f"{proc.stderr.strip()[:400]}",
            )

        manifest = out_dir / "AndroidManifest.xml"
        smali_dirs = sorted(str(p) for p in out_dir.glob("smali*"))

        return {
            "output_dir": str(out_dir),
            "apk_sha256": sha,
            "manifest_path": str(manifest) if manifest.exists() else None,
            "smali_dirs": smali_dirs,
            "assets_dir": str(out_dir / "assets") if (out_dir / "assets").exists() else None,
            "res_dir": str(out_dir / "res") if (out_dir / "res").exists() else None,
        }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
