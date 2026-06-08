"""drozer wrapper — component-permission audit against an installed app.

drozer is a runtime introspection toolkit for Android. It runs a server-side
agent on the target device and a client CLI on the host; the two talk over a
TCP socket (default port 31415, operator sets up `adb forward tcp:31415
tcp:31415` externally). The client exposes a console with modules for
enumerating exported components, fuzzing content providers, and probing
intent filters.

OS prerequisite: `drozer` CLI on PATH on the host. The agent (drozer-server)
also needs to be installed and started on the target device — operator
handles install plus the port-forward. This wrapper assumes both halves are
already running; it does not try to start the agent itself.

What this tool covers:

- `app.package.attacksurface <pkg>` — count of exported activities,
  receivers, providers, services, plus the debuggable flag. This is the
  first thing a reviewer wants when triaging an APK: every exported
  component is a potential entry surface for any other app on the same
  device, which is the on-device equivalent of an exposed HTTP route.
- `scanner.provider.injection -a <pkg>` — finds content providers that
  take user-controllable strings into SQL projection / selection / sort
  fields without escaping.
- `scanner.activity.browsable -a <pkg>` — enumerates BROWSABLE-tagged
  activities and their accepted URI schemes (deep-link entry points).

The returned shape matches what a VR persona wants to ask drozer about an
app in one round trip; the caller does not need to parse drozer's prose
output line-by-line.
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

# Wall-clock cap for a single drozer console command. The scanner.* modules
# can take a minute or two on large apps because they walk every exported
# provider/activity in turn. 180s leaves headroom without parking the worker
# indefinitely; the orchestration layer's per-tool semaphore further bounds
# total drozer concurrency.
_DEFAULT_TIMEOUT_S = 180

# Install hint surfaced when `drozer` is not on PATH. Mentions both halves
# (host CLI plus on-device agent) because the most common failure mode is
# operators installing the CLI but forgetting the agent APK.
_INSTALL_HINT = (
    "drozer not on PATH. Install the host CLI with `pip install drozer`, "
    "stage the on-device agent (drozer-agent.apk) separately, and forward "
    "the agent socket with `adb forward tcp:31415 tcp:31415` before "
    "calling this tool. See https://labs.withsecure.com/tools/drozer."
)

# `app.package.attacksurface` lines. drozer emits one integer per kind plus
# an optional `is debuggable` flag. The regex tolerates singular forms
# ("1 activity exported") and the "broadcast receivers" variant.
_ATTACKSURFACE_COUNT_RE = re.compile(
    r"^\s*(\d+)\s+(activit(?:y|ies)|broadcast receivers?|receivers?|"
    r"content providers?|providers?|services?)\s+exported\s*$",
)
_ATTACKSURFACE_DEBUG_RE = re.compile(r"^\s*is debuggable\s*$")

# `scanner.provider.injection` section headers. drozer groups findings under
# `Injection in Projection:` / `Injection in Selection:` / `Not Vulnerable:`.
# We record only the vulnerable categories — `Not Vulnerable` is noise for a
# security review and inflates output without adding signal.
_PROVIDER_SECTION_RE = re.compile(
    r"^(Injection in Projection|Injection in Selection|Not Vulnerable):\s*$",
)
_CONTENT_URI_RE = re.compile(r"^\s+(content://\S+)\s*$")

# `scanner.activity.browsable` block headers. drozer emits one package
# header per scanned app, then nested `Invocable URIs:` / `Classes:`
# subsections each followed by indented value lines.
_BROWSABLE_PACKAGE_RE = re.compile(r"^Package:\s+(\S+)\s*$")
_BROWSABLE_URIS_HEADER_RE = re.compile(r"^\s*Invocable URIs:\s*$")
_BROWSABLE_CLASSES_HEADER_RE = re.compile(r"^\s*Classes:\s*$")
_INDENTED_VALUE_RE = re.compile(r"^\s+(\S.*?)\s*$")


def register(mcp: Any) -> None:
    @mcp.tool()
    async def drozer_scan_apk(
        apk_path: str,
        package_name: str | None = None,
    ) -> dict[str, Any]:
        """Run a drozer component + scanner audit against an installed app.

        The APK must already be installed on the connected device with a
        matching package, and `drozer-server` must be running on the
        device with `adb forward tcp:31415 tcp:31415` in place. This tool
        only drives the host-side `drozer console connect` client.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.
                Used to extract the package name when `package_name` is
                not supplied. The local file is not uploaded anywhere —
                it serves only as a manifest source for the package id.
            package_name: Override the auto-extracted package name. Pass
                this when the APK file is unavailable locally or when
                the manifest is encrypted/obfuscated. When set, `apk_path`
                is ignored for the package-id lookup.

        Returns:
            dict with:
                `package` (str) — the package name targeted on the device
                `exported_components` (dict) — five keys:
                    `activities`, `receivers`, `providers`, `services`
                    (each an int) and `is_debuggable` (bool)
                `finder_results` (dict) — two sub-lists:
                    `provider_injection` — `[{uri, vector}, ...]` where
                        `vector` is `"projection"` or `"selection"`
                    `activity_browsable` — `[{package, invocable_uris,
                        classes}, ...]` per scanned package block

        Raises:
            FileNotFoundError: APK path does not exist AND no
                `package_name` override was supplied.
            RuntimeError: `drozer` is not on PATH, the on-device agent
                refused the connection, or a subprocess timed out.
        """
        drozer = shutil.which("drozer")
        if drozer is None:
            raise RuntimeError(_INSTALL_HINT)

        pkg = package_name or _extract_package_from_apk(apk_path)

        attacksurface_out = await _run_drozer_command(
            drozer, f"run app.package.attacksurface {pkg}",
        )
        provider_out = await _run_drozer_command(
            drozer, f"run scanner.provider.injection -a {pkg}",
        )
        browsable_out = await _run_drozer_command(
            drozer, f"run scanner.activity.browsable -a {pkg}",
        )

        return {
            "package": pkg,
            "exported_components": _parse_attacksurface(attacksurface_out),
            "finder_results": {
                "provider_injection": _parse_provider_injection(provider_out),
                "activity_browsable": _parse_activity_browsable(browsable_out),
            },
        }


async def _run_drozer_command(drozer_bin: str, command: str) -> str:
    """Drive `drozer console connect -c <command>` and return its stdout.

    Each command runs in its own subprocess, which costs ~50ms of agent
    handshake overhead per call but keeps the parser's life simple: one
    command's output is never interleaved with another's, and a failure
    in one query does not poison the others.

    Raises:
        RuntimeError: subprocess timed out, or drozer printed a clear
            connection-error marker on stderr.
    """
    cmd = [drozer_bin, "console", "connect", "-c", command]
    loop = asyncio.get_event_loop()
    try:
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=_DEFAULT_TIMEOUT_S,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"drozer timed out after {_DEFAULT_TIMEOUT_S}s on `{command}`",
        ) from exc

    # drozer exits non-zero on connection failure. The agent prints a
    # distinctive "could not connect" or "Could not find the drozer agent"
    # line on stderr; both signal a transport problem the caller can act
    # on. Other non-zero exits (rare — usually module-internal errors)
    # are surfaced as RuntimeError too because the resulting stdout is
    # likely truncated and parsing it would silently lie about coverage.
    if proc.returncode != 0:
        stderr_blob = (proc.stderr or "").strip()
        lowered = stderr_blob.lower()
        if "could not connect" in lowered or "drozer agent" in lowered:
            raise RuntimeError(
                f"drozer console connect failed: {stderr_blob}",
            )
        raise RuntimeError(
            f"drozer `{command}` exited {proc.returncode}: {stderr_blob}",
        )
    return proc.stdout


def _extract_package_from_apk(apk_path: str) -> str:
    """Read the package name from an APK manifest via androguard.

    Local helper so the tool's signature stays narrow (apk_path only).
    Tests pass `package_name=` directly to bypass this path.

    Raises:
        FileNotFoundError: APK does not exist.
        RuntimeError: manifest could not be parsed (corrupt zip,
            non-APK content, missing AndroidManifest.xml).
    """
    apk = Path(apk_path).expanduser().resolve()
    if not apk.exists():
        raise FileNotFoundError(f"apk not found: {apk}")

    from androguard.core.apk import APK  # local import keeps cold-start fast

    try:
        return APK(str(apk)).get_package()
    except Exception as exc:  # noqa: BLE001 — androguard's error surface is genuinely broad
        raise RuntimeError(
            f"could not extract package name from {apk}: "
            f"{type(exc).__name__}: {exc}",
        ) from exc


def _parse_attacksurface(stdout: str) -> dict[str, Any]:
    """Parse `run app.package.attacksurface <pkg>` output.

    Tolerant of singular/plural and "broadcast receivers" vs "receivers"
    drift across drozer versions. Unrecognized kinds are ignored rather
    than raising — drozer occasionally adds new lines (e.g. shared-uid
    notices) that are not load-bearing for the count tally.
    """
    counts: dict[str, int] = {
        "activities": 0,
        "receivers": 0,
        "providers": 0,
        "services": 0,
    }
    debuggable = False
    for line in stdout.splitlines():
        m = _ATTACKSURFACE_COUNT_RE.match(line)
        if m:
            kind = _normalize_component_kind(m.group(2))
            if kind in counts:
                counts[kind] = int(m.group(1))
            continue
        if _ATTACKSURFACE_DEBUG_RE.match(line):
            debuggable = True
    return {**counts, "is_debuggable": debuggable}


def _normalize_component_kind(token: str) -> str:
    """Map drozer's kind tokens (plural/singular, "broadcast receivers")
    onto the canonical four-key vocabulary used in the return shape."""
    t = token.lower()
    if "activit" in t:
        return "activities"
    if "receiver" in t:
        return "receivers"
    if "provider" in t:
        return "providers"
    if "service" in t:
        return "services"
    return "unknown"


def _parse_provider_injection(stdout: str) -> list[dict[str, str]]:
    """Parse `scanner.provider.injection -a <pkg>` output.

    Returns a flat list of `{uri, vector}` dicts where `vector` is one
    of `"projection"` / `"selection"`. URIs under `Not Vulnerable:` are
    dropped — they are not findings.
    """
    section_to_vector = {
        "Injection in Projection": "projection",
        "Injection in Selection": "selection",
    }
    findings: list[dict[str, str]] = []
    current_vector: str | None = None
    for line in stdout.splitlines():
        m_section = _PROVIDER_SECTION_RE.match(line)
        if m_section:
            section = m_section.group(1)
            current_vector = section_to_vector.get(section)
            continue
        if current_vector is None:
            continue
        m_uri = _CONTENT_URI_RE.match(line)
        if m_uri:
            findings.append({"uri": m_uri.group(1), "vector": current_vector})
    return findings


def _parse_activity_browsable(stdout: str) -> list[dict[str, Any]]:
    """Parse `scanner.activity.browsable -a <pkg>` output.

    Returns one entry per `Package:` block:
        {"package": str, "invocable_uris": [str, ...], "classes": [str, ...]}

    drozer normally emits one package block per scan when called with
    `-a <pkg>`, but nested blocks have shown up in third-party forks; the
    parser tolerates them by treating each `Package:` header as the start
    of a new entry and finalising the previous one.
    """
    findings: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_uris = False
    in_classes = False
    for line in stdout.splitlines():
        m_pkg = _BROWSABLE_PACKAGE_RE.match(line)
        if m_pkg:
            if current is not None:
                findings.append(current)
            current = {
                "package": m_pkg.group(1),
                "invocable_uris": [],
                "classes": [],
            }
            in_uris = False
            in_classes = False
            continue
        if current is None:
            continue
        if _BROWSABLE_URIS_HEADER_RE.match(line):
            in_uris, in_classes = True, False
            continue
        if _BROWSABLE_CLASSES_HEADER_RE.match(line):
            in_uris, in_classes = False, True
            continue
        m_val = _INDENTED_VALUE_RE.match(line)
        if not m_val:
            continue
        if in_uris:
            current["invocable_uris"].append(m_val.group(1))
        elif in_classes:
            current["classes"].append(m_val.group(1))
    if current is not None:
        findings.append(current)
    return findings
