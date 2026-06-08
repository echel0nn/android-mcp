"""adb facade — devices, install, uninstall, logcat, dumpsys.

`adb` is the Android Debug Bridge — the host CLI half of the platform
debugger. It talks to `adbd` on the device over USB or a TCP transport
(`adb connect <host>:<port>`). One adb-server process per host
multiplexes every command across every reachable device, so multiple
concurrent invocations are safe; the per-call cost is the few-ms
round-trip to that server.

OS prerequisite: `adb` on PATH. Ships with Android SDK platform-tools
(`sdkmanager 'platform-tools'`). On Debian/Ubuntu the
`android-tools-adb` package is the easiest install path. The server
side (`adbd`) lives on the device — operator handles enabling USB
debugging and authorizing the host fingerprint outside this tool.

What this tool covers:

- `adb_devices` — list every reachable device with state and metadata.
  The only handler that does not take `device_serial`, because picking
  a device is the entire point of the call.
- `adb_install` — push an APK to a specific device. Never picks a
  device implicitly — multi-device hosts (CI, emulator + USB phone)
  must spell out which transport to use.
- `adb_uninstall` — remove a package from a specific device.
- `adb_logcat_capture` — collect the device log for a bounded window.
  Uses subprocess timeout as the kill signal — logcat naturally runs
  forever, so the wall-clock cap IS the capture window.
- `adb_dumpsys` — query a single system service (`activity`,
  `package`, `meminfo`, `connectivity`, ...). The dumpsys output is
  the canonical structured view of each service's runtime state.

Every handler takes an explicit `device_serial` for non-`devices`
operations. The acceptance criterion is deliberate: implicit
single-device assumptions break the moment a CI runner attaches a
second emulator or the operator plugs in a phone next to the running
test farm. Forcing the caller to spell out the target keeps the
behavior deterministic across topologies.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Default subprocess timeout for adb calls. 30s covers `devices`,
# `uninstall`, and `dumpsys` comfortably; `install` of a multi-hundred-MB
# APK is the only case that genuinely needs the override-up-to-300s
# escape hatch.
_DEFAULT_TIMEOUT_S = 30

# Hard ceiling on caller-supplied timeout / logcat duration. Anything
# above 300s should run outside this MCP (the per-tool semaphore would
# otherwise hold a slot for minutes and starve sibling requests).
_MAX_TIMEOUT_S = 300

# Install hint surfaced when `adb` is not on PATH. Names the canonical
# install routes for the three host platforms operators run on.
_INSTALL_HINT = (
    "adb not on PATH. Install the Android SDK platform-tools "
    "(`sdkmanager 'platform-tools'` from the Android SDK manager, or "
    "`apt install android-tools-adb` on Debian/Ubuntu, or `brew install "
    "android-platform-tools` on macOS) and add the platform-tools "
    "directory to PATH."
)

# Lines in `adb devices -l` output. The first line is always
# "List of devices attached"; subsequent rows are `<serial>\s+<state>`
# optionally followed by space-separated `key:value` metadata tokens.
_DEVICE_LINE_RE = re.compile(r"^(\S+)\s+(\S+)(?:\s+(.*))?$")
_KV_TOKEN_RE = re.compile(r"^([a-z_]+):(.+)$")

# Successful logcat lines look like `MM-DD HH:MM:SS.mmm  PID  TID L TAG: msg`
# under `-v threadtime`. We do not parse them — the caller gets raw
# lines because every consumer wants different fields. The split on
# newlines is enough structure for the return shape.

# Keys we recognize in `adb devices -l` extras. Anything outside this
# set falls into the `extras` bucket so we keep the canonical fields
# typed without losing forward-compat metadata adb may add later.
_KNOWN_DEVICE_KEYS = frozenset({
    "product", "model", "device", "transport_id", "usb",
})


def register(mcp: Any) -> None:
    @mcp.tool()
    async def adb_devices(timeout_s: int = _DEFAULT_TIMEOUT_S) -> dict[str, Any]:
        """List every device the local adb server can reach.

        Drives `adb devices -l` and parses the long-format output into
        structured rows.

        Args:
            timeout_s: Wall-clock cap for the subprocess. Default 30s,
                hard ceiling 300s.

        Returns:
            dict with `devices` — a list of `{serial, state, product,
            model, device, transport_id, usb, extras}` rows. `state` is
            one of `"device"` (ready), `"offline"`, `"unauthorized"`,
            `"recovery"`, `"sideload"`, `"bootloader"`, `"no permissions"`,
            `"connecting"`. Metadata fields are empty strings when adb
            does not report them; `extras` holds any unknown keys
            verbatim so we do not silently drop forward-compat fields.

        Raises:
            RuntimeError: `adb` not on PATH, subprocess timed out, or
                the adb server reported a non-zero exit.
            ValueError: `timeout_s` outside (0, 300].
        """
        _validate_timeout(timeout_s)
        adb = _resolve_adb()

        proc = await _run_adb([adb, "devices", "-l"], timeout_s=timeout_s)
        _require_success(proc, "adb devices")
        return {"devices": _parse_devices_output(proc.stdout)}

    @mcp.tool()
    async def adb_install(
        device_serial: str,
        apk_path: str,
        timeout_s: int = _DEFAULT_TIMEOUT_S,
    ) -> dict[str, Any]:
        """Install an APK onto a specific device.

        Drives `adb -s <serial> install <apk_path>`. Returns the
        adb-reported success flag plus the full stdout/stderr so a
        caller can inspect failure reasons (signature mismatch, version
        downgrade, insufficient storage, etc.) without re-running.

        Args:
            device_serial: Target device transport id from
                `adb_devices`. Required — never picks a device
                implicitly.
            apk_path: Absolute path to the APK on the server
                filesystem.
            timeout_s: Wall-clock cap for the install subprocess.
                Default 30s, hard ceiling 300s. Override for large
                APKs (a 300MB game APK can take ~minute to push over
                USB 2).

        Returns:
            dict with `success` (bool — adb printed "Success"),
            `device_serial`, `apk_path` (resolved absolute), `stdout`,
            `stderr`, `exit_code`.

        Raises:
            FileNotFoundError: APK path does not exist.
            ValueError: `device_serial` empty, `apk_path` is a
                directory, or `timeout_s` outside (0, 300].
            RuntimeError: `adb` not on PATH, or the subprocess timed
                out.
        """
        _validate_device_serial(device_serial)
        _validate_timeout(timeout_s)
        adb = _resolve_adb()

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")
        if not apk.is_file():
            raise ValueError(f"not a file: {apk}")

        cmd = [adb, "-s", device_serial, "install", str(apk)]
        proc = await _run_adb(cmd, timeout_s=timeout_s)

        # `adb install` prints "Success" on stdout when the install
        # completes. A non-zero exit OR the absence of that token both
        # signal failure — adb has shipped at least one bug where exit
        # code lied about a failed install, so we cross-check the
        # stdout marker too.
        stdout = proc.stdout or ""
        success = proc.returncode == 0 and "Success" in stdout

        return {
            "success": success,
            "device_serial": device_serial,
            "apk_path": str(apk),
            "stdout": stdout,
            "stderr": proc.stderr or "",
            "exit_code": proc.returncode,
        }

    @mcp.tool()
    async def adb_uninstall(
        device_serial: str,
        package_name: str,
        timeout_s: int = _DEFAULT_TIMEOUT_S,
    ) -> dict[str, Any]:
        """Uninstall a package from a specific device.

        Drives `adb -s <serial> uninstall <package_name>`. The package
        name is the manifest's `package` attribute, not the APK's
        display name — caller resolves it via androguard / aapt before
        calling.

        Args:
            device_serial: Target device transport id.
            package_name: Java-style package name, e.g.
                `com.example.myapp`.
            timeout_s: Wall-clock cap. Default 30s, hard ceiling 300s.

        Returns:
            dict with `success` (bool — adb printed "Success"),
            `device_serial`, `package_name`, `stdout`, `stderr`,
            `exit_code`.

        Raises:
            ValueError: `device_serial` or `package_name` empty, or
                `timeout_s` outside (0, 300].
            RuntimeError: `adb` not on PATH, or the subprocess timed
                out.
        """
        _validate_device_serial(device_serial)
        _validate_non_empty(package_name, "package_name")
        _validate_timeout(timeout_s)
        adb = _resolve_adb()

        cmd = [adb, "-s", device_serial, "uninstall", package_name]
        proc = await _run_adb(cmd, timeout_s=timeout_s)

        stdout = proc.stdout or ""
        # `adb uninstall` prints `Success` on success; `Failure [<reason>]`
        # when the package was missing or a system app blocked removal.
        # Either way exit code can be 0 — the marker is the truth.
        success = "Success" in stdout

        return {
            "success": success,
            "device_serial": device_serial,
            "package_name": package_name,
            "stdout": stdout,
            "stderr": proc.stderr or "",
            "exit_code": proc.returncode,
        }

    @mcp.tool()
    async def adb_logcat_capture(
        device_serial: str,
        duration_s: int = _DEFAULT_TIMEOUT_S,
        filter_tag: str | None = None,
    ) -> dict[str, Any]:
        """Capture device log output for a bounded window.

        Drives `adb -s <serial> logcat -v threadtime [-s <tag>:*]` for
        `duration_s` seconds, then kills the subprocess and returns the
        captured lines. logcat naturally streams forever; the
        subprocess timeout IS the capture window.

        First runs `adb -s <serial> logcat -c` to clear the ring
        buffer so the captured window starts from a clean slate. That
        avoids returning hours-old startup spam alongside the
        operator-relevant lines.

        Args:
            device_serial: Target device transport id.
            duration_s: Capture window in seconds. Default 30s, hard
                ceiling 300s.
            filter_tag: Optional log tag to scope the capture to (e.g.
                `"ActivityManager"`, `"OkHttp"`). Passed as
                `<filter_tag>:*` so all priorities for that tag flow
                through. None captures every tag at default verbosity.

        Returns:
            dict with `device_serial`, `duration_s`, `filter_tag`,
            `line_count`, and `lines` (list of raw threadtime lines —
            caller parses fields as needed).

        Raises:
            ValueError: `device_serial` empty, or `duration_s` outside
                (0, 300].
            RuntimeError: `adb` not on PATH, the clear-buffer step
                failed, or the subprocess died before the timeout fired
                (logcat exiting on its own usually means transport
                drop — not what the caller asked for).
        """
        _validate_device_serial(device_serial)
        _validate_timeout(duration_s, name="duration_s")
        adb = _resolve_adb()

        # Clear the ring buffer so the captured window does not include
        # log lines that pre-date the call. A short timeout is fine —
        # `logcat -c` returns instantly when the transport is healthy.
        clear_proc = await _run_adb(
            [adb, "-s", device_serial, "logcat", "-c"],
            timeout_s=_DEFAULT_TIMEOUT_S,
        )
        _require_success(clear_proc, "adb logcat -c")

        cmd = [adb, "-s", device_serial, "logcat", "-v", "threadtime"]
        if filter_tag:
            # `-s <tag>:*` filters to one tag at all priorities. Equivalent
            # to `*:S <tag>:*` (silence everything, then unmute the tag) —
            # `-s` is the short form and works on every adb version that
            # ships with current platform-tools.
            cmd.extend(["-s", f"{filter_tag}:*"])

        # logcat runs forever; subprocess timeout is the expected
        # termination. The exception carries the captured stdout on its
        # `.stdout` attribute when `capture_output=True` (Python 3.8+).
        loop = asyncio.get_event_loop()
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(  # noqa: S603
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=duration_s,
                ),
            )
        except subprocess.TimeoutExpired as exc:
            # Expected path — logcat was killed because we hit the
            # capture window. Whatever it managed to flush before the
            # kill signal is the answer.
            captured = exc.stdout or ""
        else:
            # Unexpected path — logcat exited on its own inside the
            # window. Usually means the transport dropped (device
            # rebooted, USB cable yanked, network adb session timed
            # out). Surface a RuntimeError so the caller doesn't
            # silently get a too-short window.
            stderr = (proc.stderr or "").strip()
            raise RuntimeError(
                f"adb logcat exited unexpectedly after "
                f"<{duration_s}s on {device_serial}: "
                f"returncode={proc.returncode} stderr={stderr!r}",
            )

        # The captured blob may be bytes-decoded with the platform
        # default codec; on Windows that occasionally produces \r\n
        # line endings inside the captured str. splitlines() handles
        # both forms uniformly, then we filter trailing empties.
        lines = [line for line in captured.splitlines() if line]

        return {
            "device_serial": device_serial,
            "duration_s": duration_s,
            "filter_tag": filter_tag,
            "line_count": len(lines),
            "lines": lines,
        }

    @mcp.tool()
    async def adb_dumpsys(
        device_serial: str,
        service: str,
        timeout_s: int = _DEFAULT_TIMEOUT_S,
    ) -> dict[str, Any]:
        """Query a single device system service via dumpsys.

        Drives `adb -s <serial> shell dumpsys <service>`. Common
        services worth knowing about: `activity` (foreground app +
        task stack), `package <pkg>` (installed app metadata),
        `meminfo <pkg>` (per-app memory profile), `connectivity`
        (network state), `battery` (charge + temperature),
        `netstats detail` (per-uid byte counts), `wifi` (current
        AP + scan results).

        Args:
            device_serial: Target device transport id.
            service: dumpsys service name (anything `adb shell dumpsys
                -l` lists). The string is passed verbatim through
                `adb shell` — multi-word arguments like
                `"package com.example"` work as expected.
            timeout_s: Wall-clock cap. Default 30s, hard ceiling 300s.

        Returns:
            dict with `device_serial`, `service`, `output` (raw
            dumpsys stdout — caller parses it; service formats vary),
            `stderr`, `exit_code`. Caller decides what to do with a
            non-zero exit — some services exit 1 even on a valid
            dump.

        Raises:
            ValueError: `device_serial` or `service` empty, or
                `timeout_s` outside (0, 300].
            RuntimeError: `adb` not on PATH, or the subprocess timed
                out.
        """
        _validate_device_serial(device_serial)
        _validate_non_empty(service, "service")
        _validate_timeout(timeout_s)
        adb = _resolve_adb()

        # `service` is intentionally not split — pass through to shell
        # so the caller controls argument tokenization. The whole
        # `shell` arg becomes one string adb forwards to the device's
        # /system/bin/sh, matching how operators run dumpsys at the
        # adb shell prompt.
        cmd = [adb, "-s", device_serial, "shell", f"dumpsys {service}"]
        proc = await _run_adb(cmd, timeout_s=timeout_s)

        return {
            "device_serial": device_serial,
            "service": service,
            "output": proc.stdout or "",
            "stderr": proc.stderr or "",
            "exit_code": proc.returncode,
        }


def _resolve_adb() -> str:
    """Return the absolute path to `adb` or raise the install hint."""
    adb = shutil.which("adb")
    if adb is None:
        raise RuntimeError(_INSTALL_HINT)
    return adb


def _validate_device_serial(device_serial: str) -> None:
    """Reject empty device_serial — implicit single-device assumption
    is the bug the acceptance criterion exists to prevent."""
    if not isinstance(device_serial, str) or not device_serial.strip():
        raise ValueError(
            "device_serial is required and must be a non-empty string; "
            "obtain it from adb_devices()",
        )


def _validate_non_empty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required and must be a non-empty string")


def _validate_timeout(value: int, *, name: str = "timeout_s") -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if value <= 0 or value > _MAX_TIMEOUT_S:
        raise ValueError(
            f"{name} must be in (0, {_MAX_TIMEOUT_S}], got {value}",
        )


async def _run_adb(cmd: list[str], *, timeout_s: int) -> subprocess.CompletedProcess[str]:
    """Run an adb subprocess off the event loop with the standard envelope.

    Wraps `subprocess.run` in `loop.run_in_executor` so the FastAPI
    event loop never blocks. Captures stdout + stderr as text. Maps
    `subprocess.TimeoutExpired` to RuntimeError with a clean message —
    the asyncio loop should never see the raw subprocess exception.
    """
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(
            None,
            lambda: subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        # `cmd[0]` is the resolved adb path; show only the leaf for
        # readability. Subsequent args identify which call timed out.
        leaf = Path(cmd[0]).name
        rest = " ".join(cmd[1:])
        raise RuntimeError(
            f"{leaf} {rest} timed out after {timeout_s}s",
        ) from exc


def _require_success(
    proc: subprocess.CompletedProcess[str],
    label: str,
) -> None:
    """Raise RuntimeError when an adb call failed at the transport level.

    Used for commands where a non-zero exit means the call did not
    even reach the device — e.g. `adb devices` failing means the
    local server is dead. For commands where non-zero exit carries
    useful diagnostics (install, uninstall, dumpsys), the caller
    inspects `returncode` directly instead.
    """
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(
            f"{label} exited {proc.returncode}: {stderr or '<no stderr>'}",
        )


def _parse_devices_output(stdout: str) -> list[dict[str, Any]]:
    """Parse `adb devices -l` output into structured rows.

    The first non-blank line is always the literal header
    "List of devices attached" — skip it. Every subsequent non-blank
    line is `<serial>\\s+<state>` optionally followed by space-separated
    `key:value` metadata tokens (`product:`, `model:`, `device:`,
    `transport_id:`, `usb:`). Unknown keys land in `extras` so we do
    not silently drop forward-compat fields adb may add.

    Tolerates:
    - leading/trailing whitespace on rows
    - blank lines between header and rows (some adb builds emit one)
    - missing metadata block (offline / unauthorized devices)
    - extra warning lines from `adb` (e.g. server-start banners)
    """
    devices: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("List of devices attached"):
            continue
        # Skip adb server warnings/banners that occasionally precede the
        # device list ("* daemon not running; starting now ...",
        # "* daemon started successfully").
        if line.startswith("*"):
            continue
        m = _DEVICE_LINE_RE.match(line)
        if not m:
            continue
        serial, state, meta = m.group(1), m.group(2), m.group(3) or ""
        row: dict[str, Any] = {
            "serial": serial,
            "state": state,
            "product": "",
            "model": "",
            "device": "",
            "transport_id": "",
            "usb": "",
            "extras": {},
        }
        for token in meta.split():
            km = _KV_TOKEN_RE.match(token)
            if not km:
                continue
            key, value = km.group(1), km.group(2)
            if key in _KNOWN_DEVICE_KEYS:
                row[key] = value
            else:
                row["extras"][key] = value
        devices.append(row)
    return devices
