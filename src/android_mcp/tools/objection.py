"""objection wrapper — patch APKs with frida-gadget; drive REPL commands.

objection (https://github.com/sensepost/objection) is a Frida-based
mobile exploration toolkit. Two surfaces are wrapped here:

- ``patchapk`` — unpacks an APK with apktool, injects
  ``libfrida-gadget.so`` for a target architecture, repacks, zipaligns,
  and signs with objection's bundled debug key. The patched APK boots
  the gadget on launch so Frida tooling can attach without root or a
  separate ``frida-server`` running on the device.
- ``start`` / ``run`` — drives an objection REPL session against a
  device that already has frida-server (or the patched gadget) running.
  Used for non-interactive command execution after attach.

The wrapper shells out to the ``objection`` CLI rather than importing
the package because:

1. ``objection``'s ``commands.mobile_packages.patch_android_apk``
   function has side-effects on process cwd, calls ``click.secho``
   directly, and does ``input('Press ENTER ...')`` on pause flags —
   none of which compose well inside an async MCP handler.
2. ``objection start`` boots a ``prompt_toolkit`` REPL that owns
   stdin/stdout/stderr; the CLI is the only stable interface.
3. The package version drift between releases is significant; the
   CLI flags are more stable than the Python API.

OS prerequisite: ``objection`` CLI on PATH. Install via
``pip install objection`` (or ``pip install 'android-mcp[scanners]'``).
On the device side, the operator runs ``frida-server`` for the
matching arch — this wrapper does NOT manage device-side processes.

Acceptance shape per PRD §A-4:

- ``objection_patch_apk(apk_path, gadget_arch, output_path=None)`` —
  shells ``objection patchapk --source <apk_path> --architecture <arch>``,
  returns ``{patched_apk_path, source_apk, architecture, stdout_tail}``.
- ``objection_explore(device_serial, package_name, script=None)`` —
  shells the objection REPL (``run`` for single commands and probe mode,
  ``start --file-commands`` for script files), returns
  ``{device_serial, package_name, mode, command, stdout, stderr, exit_code}``.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Wall-clock cap per ``patchapk`` invocation. Patching downloads the
# Frida gadget ``.so`` (~3-5 MB per arch) on first use, unpacks the APK
# with apktool, repackages, zipaligns, and signs. On a 50 MB customer
# app this routinely takes 1-3 minutes; 600s gives generous headroom
# for large apps and slow networks without parking the worker
# indefinitely. The orchestration layer's per-tool semaphore bounds
# total concurrency on top of this.
_PATCH_TIMEOUT_S = 600

# Wall-clock cap per ``explore`` invocation. Most ``objection run``
# commands return in well under a second; ``start --file-commands``
# can take longer when the script enumerates many objects. 120s is
# enough for typical exploratory work without holding the worker
# open while the operator forgets a hanging session.
_EXPLORE_TIMEOUT_S = 120

# Architecture strings objection's gadget downloader accepts. Frida
# ships gadget binaries for exactly these four Android ABIs; passing
# anything else makes objection fail at gadget-download time with a
# 404 from GitHub. We validate up front so the failure surface is
# a clean ``ValueError`` rather than a cryptic non-zero exit.
_VALID_ARCHS = frozenset({"armeabi-v7a", "arm64-v8a", "x86", "x86_64"})

# objection's source (``commands/mobile_packages.py::patch_android_apk``)
# computes the output filename as:
#     destination = source.replace('.apk', '.objection.apk')
# and writes the patched APK to
#     os.path.join(os.path.abspath('.'), os.path.basename(destination))
# When ``source`` is an absolute path (as we always pass), ``os.path.join``
# discards the cwd prefix and the file lands NEXT TO THE SOURCE — not in
# the process cwd. The wrapper still pins cwd to a temp dir so any
# stray apktool / signing temp files (which objection writes relative
# to cwd) do not pollute the worker's working directory.
_OBJECTION_OUTPUT_SUFFIX = ".objection.apk"
_OBJECTION_OUTPUT_REPLACES = ".apk"

# Truncate captured stdout to this many trailing bytes before returning.
# objection's stdout is colourful and verbose (apktool log, gadget
# download progress, signing report); 2 KB keeps the diagnostic
# usefulness without blowing up the JSON response envelope.
_STDOUT_TAIL_BYTES = 2048

_INSTALL_HINT = (
    "objection not on PATH. Install with `pip install objection` "
    "(or `pip install 'android-mcp[scanners]'`); the wrapper shells "
    "out to the `objection` CLI rather than importing the package "
    "because objection's CLI is the stable surface and its internal "
    "patcher API changes between releases. See "
    "https://github.com/sensepost/objection."
)


def register(mcp: Any) -> None:
    @mcp.tool()
    async def objection_patch_apk(
        apk_path: str,
        gadget_arch: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Patch an APK with the Frida gadget via ``objection patchapk``.

        objection unpacks the APK with apktool, injects
        ``libfrida-gadget.so`` for the target architecture, repacks,
        zipaligns, and signs the result with objection's bundled debug
        key. The patched APK boots the gadget on launch so Frida tooling
        can attach without root or a separate ``frida-server``.

        Args:
            apk_path: Absolute path to the source APK. Must exist and
                must be a regular file whose basename contains ``.apk``
                (objection's output-filename derivation requires the
                literal ``.apk`` token to substitute).
            gadget_arch: Target Android ABI for the gadget. One of
                ``"armeabi-v7a"``, ``"arm64-v8a"``, ``"x86"``, or
                ``"x86_64"``. The arch MUST match the device the
                patched APK will be installed on — a v7a-patched APK
                refuses to launch on an arm64-only device because
                the gadget ``.so`` cannot be loaded.
            output_path: Optional destination for the patched APK. When
                ``None``, the file is left where objection placed it
                (next to the source, named
                ``<source-stem>.objection.apk``) and that path is
                returned. When set, the file is moved there; the
                parent directory is created if missing.

        Returns:
            dict with:
                ``patched_apk_path`` (str) — absolute path to the
                    patched APK on disk
                ``source_apk`` (str) — resolved absolute source path
                ``architecture`` (str) — passed-through gadget arch
                ``stdout_tail`` (str) — trailing ~2 KB of objection's
                    stdout (gadget version, apktool log, signing
                    report) for diagnostic display

        Raises:
            FileNotFoundError: ``apk_path`` does not resolve.
            ValueError: ``apk_path`` is not a regular file, its
                basename does not contain ``.apk``, or ``gadget_arch``
                is not in the supported set.
            RuntimeError: ``objection`` is not on PATH, the subprocess
                timed out, objection exited non-zero, or the expected
                output APK did not materialise.
        """
        objection = shutil.which("objection")
        if objection is None:
            raise RuntimeError(_INSTALL_HINT)

        if gadget_arch not in _VALID_ARCHS:
            raise ValueError(
                f"gadget_arch must be one of {sorted(_VALID_ARCHS)}, "
                f"got {gadget_arch!r}",
            )

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        # Mirror objection's own ``destination = source.replace('.apk',
        # '.objection.apk')`` so we can find the file objection produces.
        # Reject filenames without ``.apk`` early — otherwise the discovery
        # step below would search for a file that objection never names.
        expected_filename = apk.name.replace(
            _OBJECTION_OUTPUT_REPLACES, _OBJECTION_OUTPUT_SUFFIX,
        )
        if expected_filename == apk.name:
            raise ValueError(
                f"apk filename must contain '.apk', got {apk.name!r}",
            )
        produced_path = apk.parent / expected_filename

        with tempfile.TemporaryDirectory(prefix="objection-patch-") as tmp:
            work_dir = Path(tmp)
            cmd = [
                objection,
                "patchapk",
                "--source", str(apk),
                "--architecture", gadget_arch,
            ]

            loop = asyncio.get_event_loop()
            try:
                proc = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(  # noqa: S603
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=_PATCH_TIMEOUT_S,
                        cwd=str(work_dir),
                    ),
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"objection patchapk timed out after "
                    f"{_PATCH_TIMEOUT_S}s on {apk}",
                ) from exc

            if proc.returncode != 0:
                stderr_blob = (proc.stderr or "").strip()
                raise RuntimeError(
                    f"objection patchapk exited {proc.returncode}: "
                    f"{stderr_blob or '<no stderr>'}",
                )

            if not produced_path.exists():
                raise RuntimeError(
                    f"objection did not produce {produced_path}; "
                    f"stdout was: "
                    f"{(proc.stdout or '').strip() or '<empty>'}",
                )

            if output_path is not None:
                destination = Path(output_path).expanduser().resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(produced_path), str(destination))
                final_path = destination
            else:
                final_path = produced_path

            return {
                "patched_apk_path": str(final_path),
                "source_apk": str(apk),
                "architecture": gadget_arch,
                "stdout_tail": (proc.stdout or "")[-_STDOUT_TAIL_BYTES:],
            }

    @mcp.tool()
    async def objection_explore(
        device_serial: str,
        package_name: str,
        script: str | None = None,
    ) -> dict[str, Any]:
        """Run an objection REPL command (or default probe) against a device.

        objection's REPL is interactive by default; this wrapper drives
        it non-interactively in one of three modes selected from
        ``script``:

        - **probe** (``script=None``) — runs ``objection ... run env.android``
          to confirm the wrapper can attach to the target. Useful as
          a connectivity smoke-test before bigger workflows.
        - **command** (``script`` is any string that does not resolve
          to an existing file) — runs that string as a single REPL
          command via ``objection ... run <script>``. Example values:
          ``"env"``, ``"android root disable"``,
          ``"android hooking list classes"``.
        - **file_commands** (``script`` resolves to an existing file
          on disk) — feeds the file to
          ``objection ... start --quiet --file-commands <path>``. The
          file holds newline-separated objection REPL commands; the
          REPL exits on EOF once they finish (stdin is closed so the
          prompt cannot wait for input).

        The device must have ``frida-server`` running on the matching
        arch, or the target APK must have been patched with
        ``objection_patch_apk`` so its gadget is live. The operator
        drives the device-side process externally — this wrapper does
        NOT manage frida-server.

        Args:
            device_serial: adb device serial (e.g. ``"emulator-5554"``,
                a 16-hex USB serial, or ``"127.0.0.1:5555"`` for a
                network-attached device).
            package_name: Android package id to attach to (e.g.
                ``"com.vodafone.selfservis"``).
            script: One of ``None`` (probe mode), a string that does
                NOT resolve to a file (command mode), or a path to an
                existing file (file-commands mode). See the mode
                descriptions above.

        Returns:
            dict with:
                ``device_serial``, ``package_name`` — passed through
                ``mode`` (str) — one of ``"probe"``, ``"command"``,
                    ``"file_commands"``
                ``command`` (list[str]) — argv objection was invoked
                    with (excluding stdin redirection)
                ``stdout`` (str) — captured stdout
                ``stderr`` (str) — captured stderr
                ``exit_code`` (int) — objection's exit code

        Raises:
            ValueError: ``device_serial`` or ``package_name`` is empty.
            RuntimeError: ``objection`` is not on PATH, or the
                subprocess timed out.
        """
        objection = shutil.which("objection")
        if objection is None:
            raise RuntimeError(_INSTALL_HINT)
        if not device_serial:
            raise ValueError("device_serial must be non-empty")
        if not package_name:
            raise ValueError("package_name must be non-empty")

        base_cmd = [
            objection,
            "--serial", device_serial,
            "--name", package_name,
        ]

        mode: str
        cmd: list[str]
        if script is None:
            mode = "probe"
            cmd = [*base_cmd, "run", "env.android"]
        else:
            script_path = Path(script).expanduser()
            if script_path.exists() and script_path.is_file():
                mode = "file_commands"
                cmd = [
                    *base_cmd,
                    "start", "--quiet",
                    "--file-commands", str(script_path.resolve()),
                ]
            else:
                mode = "command"
                # ``objection run`` takes its command via ``nargs=-1``
                # and joins the varargs with a space; passing the
                # script string as a single argv token keeps quoting
                # intact (the REPL sees one logical command).
                cmd = [*base_cmd, "run", script]

        loop = asyncio.get_event_loop()
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(  # noqa: S603
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_EXPLORE_TIMEOUT_S,
                    stdin=subprocess.DEVNULL,
                ),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"objection explore timed out after "
                f"{_EXPLORE_TIMEOUT_S}s "
                f"(device={device_serial}, package={package_name})",
            ) from exc

        return {
            "device_serial": device_serial,
            "package_name": package_name,
            "mode": mode,
            "command": cmd,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "exit_code": proc.returncode,
        }
