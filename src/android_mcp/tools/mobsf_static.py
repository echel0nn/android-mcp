"""MobSF static analysis client.

MobSF (Mobile Security Framework) runs as a separate HTTP service —
typically `docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf`.
This wrapper does NOT spawn it; it uploads an APK to a running MobSF
instance and pulls the JSON report.

Why not spawn? MobSF has its own DB, queue, and config; running it
from inside this MCP would duplicate the responsibility split that
audit-mcp already keeps clean. Operator owns the MobSF lifecycle.

Env vars:
    MOBSF_URL       MobSF base URL (default: http://127.0.0.1:8000)
    MOBSF_API_KEY   MobSF REST API key (required; print it once via
                    `docker exec ... mobsf-api-key`).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import requests

_log = logging.getLogger(__name__)

_DEFAULT_URL = os.environ.get("MOBSF_URL", "http://127.0.0.1:8000")
_API_KEY = os.environ.get("MOBSF_API_KEY", "")


def register(mcp: Any) -> None:
    @mcp.tool()
    async def mobsf_scan(
        apk_path: str,
        rescan: bool = False,
        timeout_seconds: int = 1800,
    ) -> dict[str, Any]:
        """Upload an APK to MobSF, trigger a static scan, return the JSON report.

        Args:
            apk_path: Absolute path to the APK on the server filesystem.
            rescan: Force re-scan even if MobSF has cached results for
                this hash.
            timeout_seconds: Total time budget for the upload+scan+report
                round-trip.

        Returns:
            MobSF's JSON report verbatim, plus an `_mobsf_url` field
            pointing at the human-readable HTML report for cross-link.

        Raises:
            RuntimeError if MOBSF_API_KEY env var is unset, MobSF is
            unreachable, or the scan returns an HTTP error.
        """
        if not _API_KEY:
            raise RuntimeError(
                "MOBSF_API_KEY env var is required. "
                "Get it from a running MobSF instance (see README).",
            )

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")

        headers = {"Authorization": _API_KEY}

        # 1. upload
        with apk.open("rb") as f:
            files = {"file": (apk.name, f, "application/octet-stream")}
            r = requests.post(
                f"{_DEFAULT_URL}/api/v1/upload",
                files=files,
                headers=headers,
                timeout=timeout_seconds,
            )
        r.raise_for_status()
        upload = r.json()
        scan_hash = upload.get("hash")
        if not scan_hash:
            raise RuntimeError(f"MobSF upload returned no hash: {upload}")

        # 2. scan
        scan_body = {"hash": scan_hash, "re_scan": "1" if rescan else "0"}
        r = requests.post(
            f"{_DEFAULT_URL}/api/v1/scan",
            data=scan_body,
            headers=headers,
            timeout=timeout_seconds,
        )
        r.raise_for_status()

        # 3. JSON report
        r = requests.post(
            f"{_DEFAULT_URL}/api/v1/report_json",
            data={"hash": scan_hash},
            headers=headers,
            timeout=timeout_seconds,
        )
        r.raise_for_status()
        report = r.json()

        report["_mobsf_url"] = f"{_DEFAULT_URL}/static_analyzer/?name={apk.name}&checksum={scan_hash}&type=apk"
        report["_scan_hash"] = scan_hash
        return report
