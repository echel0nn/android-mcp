"""androguard wrapper — Python-native APK + dex static analysis.

androguard parses the APK structure, AndroidManifest.xml, dex
bytecode, and signing certificates without needing an external tool
binary. It's the cheapest first-pass: cheap manifest + permissions +
activities + services + receivers + intent filters + cert chain in
under 5 seconds on a 50 MB APK.

When to use which:
    androguard      — fast structural facts (manifest, permissions, certs)
    apktool         — full smali + resources + AndroidManifest as text
    jadx            — readable Java (more useful for audit)
    mobsf_scan      — full vendor-quality static audit with built-in rules
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)


def register(mcp: Any) -> None:
    @mcp.tool()
    async def androguard_summary(apk_path: str) -> dict[str, Any]:
        """Pull a one-shot structural summary of an APK via androguard.

        Args:
            apk_path: Absolute path to the APK.

        Returns:
            dict with `package`, `version_name`, `version_code`,
            `min_sdk`, `target_sdk`, `permissions` (list),
            `activities` (list), `services` (list), `receivers` (list),
            `providers` (list), `main_activity`, `signing_certs`
            (list of cert summaries), `exported_components` (filtered
            list of activities/services/receivers with android:exported=true),
            `intent_filters_by_component`.
        """
        from androguard.core.apk import APK  # local import keeps cold-start fast

        apk = Path(apk_path).expanduser().resolve()
        if not apk.exists():
            raise FileNotFoundError(f"apk not found: {apk}")

        a = APK(str(apk))

        # Exported-component scan: anything with android:exported=true OR
        # with at least one <intent-filter> (Android-level convention treats
        # the latter as effectively exported on older SDKs).
        exported: list[dict[str, str]] = []
        for kind, names in (
            ("activity", a.get_activities()),
            ("service", a.get_services()),
            ("receiver", a.get_receivers()),
            ("provider", a.get_providers()),
        ):
            for name in names:
                is_exported = a.get_element(kind, "exported", name=name) == "true"
                filters = a.get_intent_filters(kind, name)
                if is_exported or filters:
                    exported.append({
                        "kind": kind,
                        "name": name,
                        "exported_attr": "true" if is_exported else "(absent; has intent-filters)",
                        "filters": filters,
                    })

        # Cert summaries — issuer/subject/serial/not_before/not_after only.
        # Full chain is heavier and rarely needed for first-pass audit.
        certs: list[dict[str, Any]] = []
        try:
            for cert_der in a.get_certificates_der_v3() or []:
                certs.append(_summarize_cert(cert_der, "v3"))
            for cert_der in a.get_certificates_der_v2() or []:
                certs.append(_summarize_cert(cert_der, "v2"))
            for cert_der in a.get_certificates_der_v1() or []:
                certs.append(_summarize_cert(cert_der, "v1"))
        except Exception as exc:  # noqa: BLE001 — cert parsing is genuinely best-effort
            certs.append({"error": f"cert parse failed: {type(exc).__name__}: {exc}"})

        return {
            "package": a.get_package(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "permissions": sorted(a.get_permissions() or []),
            "activities": sorted(a.get_activities() or []),
            "services": sorted(a.get_services() or []),
            "receivers": sorted(a.get_receivers() or []),
            "providers": sorted(a.get_providers() or []),
            "main_activity": a.get_main_activity(),
            "exported_components": exported,
            "signing_certs": certs,
        }


def _summarize_cert(cert_der: bytes, scheme: str) -> dict[str, Any]:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(cert_der)
    return {
        "scheme": scheme,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": str(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
    }
