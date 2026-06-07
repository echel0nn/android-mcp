"""jadx wrapper — dex-to-Java decompilation.

Jadx is the de-facto standard dex decompiler. It produces readable
Java source from .dex / .apk / .jar / .class with a reasonable hit
rate even on obfuscated code, plus a CFG and a string-cross-reference
index.

OS prerequisite: `jadx` CLI on PATH. Install via package manager or
download from https://github.com/skylot/jadx/releases.

Output: every decompiled tree lands under
`<workdir>/jadx-<sha256>/sources/...` with `resources/`, `lib/`, and
the `summary.json` jadx emits on success.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_DEFAULT_WORKDIR = Path(os.environ.get("ANDROID_MCP_WORKDIR", "~/.android-mcp/work")).expanduser()


def register(mcp: Any) -> None:
    @mcp.tool()
    async def jadx_decompile(
        apk_path: str,
        deobfuscate: bool = True,
        show_bad_code: bool = True,
        threads: int = 0,
    ) -> dict[str, Any]:
        """Decompile an APK / dex / jar with jadx.

        Args:
            apk_path: Absolute path to the input file.
            deobfuscate: Pass --deobf (rename obfuscated classes).
            show_bad_code: Pass --show-bad-code (emit even when
                decompiler errors leave fragments — usually wanted for
                audit work).
            threads: Decompiler thread count (0 = jadx default).

        Returns:
            dict with `output_dir`, `sha256`, `sources_dir`,
            `resources_dir`, `summary_path`, `class_count`.
        """
        target = Path(apk_path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"input not found: {target}")

        sha = _sha256_file(target)
        out_dir = _DEFAULT_WORKDIR / f"jadx-{sha[:16]}"
        out_dir.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["jadx", "-d", str(out_dir), str(target)]
        if deobfuscate:
            cmd.append("--deobf")
        if show_bad_code:
            cmd.append("--show-bad-code")
        if threads > 0:
            cmd += ["-j", str(threads)]

        loop = asyncio.get_event_loop()
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=1800),  # noqa: S603
        )

        # jadx returns non-zero when it had partial failures even with
        # --show-bad-code; treat that as a successful-with-warnings
        # outcome rather than an error. Only hard-fail when no output
        # was produced.
        sources_dir = out_dir / "sources"
        if not sources_dir.exists():
            raise RuntimeError(
                f"jadx produced no sources (exit {proc.returncode}): "
                f"{proc.stderr.strip()[:400]}",
            )

        class_count = sum(1 for _ in sources_dir.rglob("*.java"))

        return {
            "output_dir": str(out_dir),
            "sha256": sha,
            "sources_dir": str(sources_dir),
            "resources_dir": str(out_dir / "resources") if (out_dir / "resources").exists() else None,
            "summary_path": str(out_dir / "jadx.log") if (out_dir / "jadx.log").exists() else None,
            "class_count": class_count,
            "exit_code": proc.returncode,
            "had_warnings": proc.returncode != 0,
        }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
