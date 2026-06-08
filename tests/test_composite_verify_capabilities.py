"""Tests for ``composite.verify_capabilities``.

The handler reads an APK via ``androguard.core.apk.APK`` and walks
its permissions, intent-filter actions, exported components, manifest
flags, and signing-scheme blocks against the catalogue at
:data:`composite._MOBILE_CAPABILITIES`. Driving androguard end-to-end
would need a real APK on disk; the suite monkeypatches the ``APK``
constructor with a fake that exposes only the surface the handler
reads.

The mock surface mirrors androguard 4.x:
    ``get_permissions``      → list[str]
    ``get_activities``       → list[str] (also services/receivers/providers)
    ``get_intent_filters``   → dict or list of dicts
    ``get_attribute_value``  → str (manifest flag reader)
    ``get_certificates_v{1,2,3,31}``  → truthy when scheme present
    ``get_package``          → str
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------
# Test double for androguard.core.apk.APK
# ---------------------------------------------------------------------

class _FakeAPK:
    """Minimal stand-in for ``androguard.core.apk.APK``.

    Only models the read surface the handler touches. Construction
    accepts a path so the monkeypatch can swap the class wholesale
    via :func:`_install_fake_apk`.
    """

    def __init__(
        self,
        _path: str | None = None,
        *,
        package: str = "com.example.app",
        permissions: list[str] | None = None,
        activities: list[str] | None = None,
        services: list[str] | None = None,
        receivers: list[str] | None = None,
        providers: list[str] | None = None,
        intent_filters: dict[tuple[str, str], Any] | None = None,
        attribute_values: dict[tuple[str, str], str] | None = None,
        certs_v1: list[Any] | None = None,
        certs_v2: list[Any] | None = None,
        certs_v3: list[Any] | None = None,
        certs_v31: list[Any] | None = None,
    ) -> None:
        self._package = package
        self._permissions = permissions or []
        self._activities = activities or []
        self._services = services or []
        self._receivers = receivers or []
        self._providers = providers or []
        self._intent_filters = intent_filters or {}
        self._attribute_values = attribute_values or {}
        self._certs_v1 = certs_v1 or []
        self._certs_v2 = certs_v2 or []
        self._certs_v3 = certs_v3 or []
        self._certs_v31 = certs_v31 or []

    def get_package(self) -> str:
        return self._package

    def get_permissions(self) -> list[str]:
        return list(self._permissions)

    def get_activities(self) -> list[str]:
        return list(self._activities)

    def get_services(self) -> list[str]:
        return list(self._services)

    def get_receivers(self) -> list[str]:
        return list(self._receivers)

    def get_providers(self) -> list[str]:
        return list(self._providers)

    def get_intent_filters(self, kind: str, name: str) -> Any:
        return self._intent_filters.get((kind, name), {})

    def get_attribute_value(self, tag: str, attr: str, **kwargs: Any) -> str:
        # The handler passes either no kwargs (application-level) or
        # ``name=<component-name>`` (component-level). Match the same
        # convention so the fake stores both styles under one map.
        name = kwargs.get("name")
        key = (tag, attr) if name is None else (tag, attr, name)  # type: ignore[assignment]
        # Allow per-component overrides; fall back to the (tag, attr)
        # pair when no component-specific value is registered.
        if isinstance(key, tuple) and len(key) == 3:
            v = self._attribute_values.get(key)  # type: ignore[arg-type]
            if v is not None:
                return v
            return self._attribute_values.get((tag, attr), "")
        return self._attribute_values.get((tag, attr), "")

    def get_certificates_v1(self) -> list[Any]:
        return list(self._certs_v1)

    def get_certificates_v2(self) -> list[Any]:
        return list(self._certs_v2)

    def get_certificates_v3(self) -> list[Any]:
        return list(self._certs_v3)

    def get_certificates_v31(self) -> list[Any]:
        return list(self._certs_v31)


def _install_fake_apk(
    monkeypatch: pytest.MonkeyPatch,
    **fake_kwargs: Any,
) -> _FakeAPK:
    """Replace ``androguard.core.apk.APK`` with a factory returning the fake.

    Returns the configured fake so tests can read back what the handler
    saw during the call. The factory is sensitive to the path argument
    only insofar as it accepts one; everything else comes from
    ``fake_kwargs``.
    """
    fake = _FakeAPK(**fake_kwargs)

    def _factory(_path: str, *_a: Any, **_kw: Any) -> _FakeAPK:
        return fake

    import androguard.core.apk as _apk

    monkeypatch.setattr(_apk, "APK", _factory)
    return fake


# ---------------------------------------------------------------------
# Handler capture — composite.py registers >1 tool
# ---------------------------------------------------------------------

def _capture_handlers() -> dict[str, Any]:
    """Run ``register`` against a tiny FastMCP double; return name→fn map."""
    from android_mcp.composite import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn: Any) -> Any:
                captured[fn.__name__] = fn
                return fn

            return deco

    register(_MCP())
    return captured


async def _call_verify(apk_path: str) -> Any:
    handlers = _capture_handlers()
    fn = handlers.get("verify_capabilities")
    assert callable(fn), f"verify_capabilities not registered (got: {sorted(handlers)})"
    return await fn(apk_path=apk_path)


def _write_dummy_apk(tmp_path: Path) -> Path:
    """Create a non-empty file on disk so the path checks pass. Content
    is irrelevant because ``APK`` is monkeypatched away."""
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"PK\x03\x04dummy-apk-content")
    return apk


# ---------------------------------------------------------------------
# register() shape
# ---------------------------------------------------------------------

def test_register_attaches_verify_capabilities_handler() -> None:
    handlers = _capture_handlers()
    assert "verify_capabilities" in handlers, (
        f"verify_capabilities not registered (got: {sorted(handlers)})"
    )
    assert handlers["verify_capabilities"].__name__ == "verify_capabilities"


def test_register_attaches_all_three_composite_handlers() -> None:
    handlers = _capture_handlers()
    assert "find_secrets" in handlers
    assert "classify_behavior" in handlers
    assert "verify_capabilities" in handlers


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

async def test_missing_apk_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await _call_verify(str(tmp_path / "does-not-exist.apk"))


async def test_directory_apk_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        await _call_verify(str(tmp_path))


# ---------------------------------------------------------------------
# Empty APK — every catalogue capability lands in absent
# ---------------------------------------------------------------------

async def test_empty_apk_returns_full_absent_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An APK with no permissions / actions / components / certs
    produces every catalogue entry in ``absent`` and nothing in
    ``confirmed`` or ``uncategorized``."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(monkeypatch, package="com.empty.app")

    result = await _call_verify(str(apk))

    from android_mcp.composite import _MOBILE_CAPABILITIES

    assert result.package == "com.empty.app"
    assert result.confirmed == []
    assert result.uncategorized == []
    absent_names = {item.name for item in result.absent}
    assert absent_names == set(_MOBILE_CAPABILITIES.keys())


async def test_apk_path_normalized_to_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(monkeypatch)

    result = await _call_verify(str(apk))

    # Path.resolve() normalizes the path; the returned string should
    # equal the resolved form, not the (potentially-relative) input.
    assert result.apk_path == str(apk.resolve())


# ---------------------------------------------------------------------
# Permission-driven evidence
# ---------------------------------------------------------------------

async def test_internet_permission_lands_in_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch, permissions=["android.permission.INTERNET"]
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "internet_access" in confirmed_by_name
    cap = confirmed_by_name["internet_access"]
    assert any(
        e.source == "permission" and e.detail == "android.permission.INTERNET"
        for e in cap.evidence
    )


async def test_multiple_permissions_aggregate_into_evidence_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        permissions=[
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        ],
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    cap = confirmed_by_name["internet_access"]
    details = sorted(
        e.detail for e in cap.evidence if e.source == "permission"
    )
    assert details == [
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.INTERNET",
    ]


async def test_known_permission_does_not_appear_in_uncategorized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch, permissions=["android.permission.INTERNET"]
    )

    result = await _call_verify(str(apk))

    uncat_names = {u.name for u in result.uncategorized}
    assert "android.permission.INTERNET" not in uncat_names


# ---------------------------------------------------------------------
# Intent-action evidence
# ---------------------------------------------------------------------

async def test_intent_action_lands_in_confirmed_via_intent_action_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A receiver listening for BOOT_COMPLETED triggers
    background_execution via intent_action evidence — even when no
    catalogue permission is declared."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        receivers=["com.example.app.BootReceiver"],
        intent_filters={
            ("receiver", "com.example.app.BootReceiver"): {
                "action": ["android.intent.action.BOOT_COMPLETED"],
                "category": [],
            },
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "background_execution" in confirmed_by_name
    cap = confirmed_by_name["background_execution"]
    assert any(
        e.source == "intent_action"
        and e.detail == "android.intent.action.BOOT_COMPLETED"
        for e in cap.evidence
    )


# ---------------------------------------------------------------------
# Manifest-flag evidence
# ---------------------------------------------------------------------

async def test_debuggable_flag_lands_in_confirmed_via_manifest_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        attribute_values={("application", "debuggable"): "true"},
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "debuggable_build" in confirmed_by_name
    cap = confirmed_by_name["debuggable_build"]
    assert any(
        e.source == "manifest_flag"
        and e.detail == "application.debuggable=true"
        for e in cap.evidence
    )


async def test_debuggable_flag_false_does_not_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """debuggable=false must NOT trigger the capability — the
    catalogue's expected value is the literal string ``true``."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        attribute_values={("application", "debuggable"): "false"},
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    absent_by_name = {a.name for a in result.absent}
    assert "debuggable_build" not in confirmed_by_name
    assert "debuggable_build" in absent_by_name


async def test_network_security_config_with_resource_ref_value_matches_none_expected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """networkSecurityConfig with ``expected=None`` means any non-empty
    value (e.g. ``@xml/network_security_config``) triggers the
    capability — the presence of the attribute is the signal."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        attribute_values={
            ("application", "networkSecurityConfig"): "@xml/network_security_config",
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "custom_network_security_config" in confirmed_by_name
    cap = confirmed_by_name["custom_network_security_config"]
    assert any(
        e.source == "manifest_flag"
        and "networkSecurityConfig" in e.detail
        for e in cap.evidence
    )


# ---------------------------------------------------------------------
# Exported components — special-case rule
# ---------------------------------------------------------------------

async def test_exported_component_via_explicit_attribute_lands_in_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        activities=["com.example.app.ExportedActivity"],
        attribute_values={
            ("activity", "exported", "com.example.app.ExportedActivity"): "true",
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "exported_components" in confirmed_by_name
    cap = confirmed_by_name["exported_components"]
    assert any(
        e.source == "exported_component"
        and e.detail == "activity:com.example.app.ExportedActivity"
        for e in cap.evidence
    )


async def test_component_with_intent_filter_implicitly_exported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A component without explicit ``exported`` BUT with any
    intent-filter still counts as exported — older Android SDKs
    treat unfiltered components as effectively reachable."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        receivers=["com.example.app.BootReceiver"],
        intent_filters={
            ("receiver", "com.example.app.BootReceiver"): {
                "action": ["android.intent.action.BOOT_COMPLETED"],
                "category": [],
            },
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "exported_components" in confirmed_by_name


async def test_component_without_export_or_filter_not_in_exported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare component (no exported attr, no intent-filter) does NOT
    drive the exported_components capability."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        activities=["com.example.app.PrivateActivity"],
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "exported_components" not in confirmed_by_name


# ---------------------------------------------------------------------
# Deep linking — VIEW + BROWSABLE pair
# ---------------------------------------------------------------------

async def test_deep_link_with_view_and_browsable_lands_in_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        activities=["com.example.app.DeepLinkActivity"],
        intent_filters={
            ("activity", "com.example.app.DeepLinkActivity"): {
                "action": ["android.intent.action.VIEW"],
                "category": ["android.intent.category.BROWSABLE"],
            },
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "deep_linking" in confirmed_by_name
    cap = confirmed_by_name["deep_linking"]
    assert any(
        e.source == "intent_filter"
        and "VIEW+BROWSABLE" in e.detail
        and "com.example.app.DeepLinkActivity" in e.detail
        for e in cap.evidence
    )


async def test_view_without_browsable_does_not_trigger_deep_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """VIEW alone without BROWSABLE is not externally invocable, so
    the deep-link capability stays absent."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        activities=["com.example.app.ViewOnly"],
        intent_filters={
            ("activity", "com.example.app.ViewOnly"): {
                "action": ["android.intent.action.VIEW"],
                "category": [],
            },
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "deep_linking" not in confirmed_by_name


# ---------------------------------------------------------------------
# Signing schemes
# ---------------------------------------------------------------------

async def test_v1_only_signing_lands_in_legacy_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(monkeypatch, certs_v1=["cert-blob"])

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "legacy_signing_scheme_only" in confirmed_by_name
    assert "modern_signing_scheme" not in confirmed_by_name


async def test_v3_signing_lands_in_modern_confirmed_not_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(monkeypatch, certs_v3=["cert-blob"])

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "modern_signing_scheme" in confirmed_by_name
    assert "legacy_signing_scheme_only" not in confirmed_by_name


async def test_v1_and_v2_signing_modern_confirmed_not_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An APK signed with both v1 and v2 is NOT legacy-only — the
    legacy_signing_scheme_only capability only fires when schemes
    == {"v1"} exactly."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch, certs_v1=["cert-blob"], certs_v2=["cert-blob"]
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "modern_signing_scheme" in confirmed_by_name
    assert "legacy_signing_scheme_only" not in confirmed_by_name


async def test_v31_signing_lands_in_modern_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(monkeypatch, certs_v31=["cert-blob"])

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    assert "modern_signing_scheme" in confirmed_by_name
    cap = confirmed_by_name["modern_signing_scheme"]
    assert any(
        e.source == "signing_scheme" and e.detail == "v3.1"
        for e in cap.evidence
    )


async def test_no_signing_means_both_signing_capabilities_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An APK with no cert blocks of any kind should not fire either
    signing capability."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(monkeypatch)

    result = await _call_verify(str(apk))

    confirmed_names = {c.name for c in result.confirmed}
    absent_names = {a.name for a in result.absent}
    assert "modern_signing_scheme" not in confirmed_names
    assert "legacy_signing_scheme_only" not in confirmed_names
    assert "modern_signing_scheme" in absent_names
    assert "legacy_signing_scheme_only" in absent_names


# ---------------------------------------------------------------------
# Uncategorized — declared-but-unknown surfaces
# ---------------------------------------------------------------------

async def test_unknown_permission_lands_in_uncategorized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        permissions=[
            "com.vendor.app.permission.CUSTOM_ACTION",
        ],
    )

    result = await _call_verify(str(apk))

    uncat = [
        u
        for u in result.uncategorized
        if u.kind == "permission"
        and u.name == "com.vendor.app.permission.CUSTOM_ACTION"
    ]
    assert len(uncat) == 1


async def test_unknown_intent_action_lands_in_uncategorized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        receivers=["com.example.app.CustomReceiver"],
        intent_filters={
            ("receiver", "com.example.app.CustomReceiver"): {
                "action": ["com.vendor.intent.action.CUSTOM_BROADCAST"],
                "category": [],
            },
        },
    )

    result = await _call_verify(str(apk))

    uncat = [
        u
        for u in result.uncategorized
        if u.kind == "intent_action"
        and u.name == "com.vendor.intent.action.CUSTOM_BROADCAST"
    ]
    assert len(uncat) == 1


async def test_known_intent_action_stays_out_of_uncategorized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        receivers=["com.example.app.BootReceiver"],
        intent_filters={
            ("receiver", "com.example.app.BootReceiver"): {
                "action": ["android.intent.action.BOOT_COMPLETED"],
                "category": [],
            },
        },
    )

    result = await _call_verify(str(apk))

    uncat_names = {u.name for u in result.uncategorized}
    assert "android.intent.action.BOOT_COMPLETED" not in uncat_names


# ---------------------------------------------------------------------
# Catalogue surface
# ---------------------------------------------------------------------

async def test_confirmed_and_absent_partition_the_catalogue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every catalogue entry appears in exactly one of ``confirmed``
    or ``absent`` — never both, never neither."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        permissions=[
            "android.permission.INTERNET",
            "android.permission.CAMERA",
        ],
        certs_v2=["cert-blob"],
    )

    result = await _call_verify(str(apk))

    from android_mcp.composite import _MOBILE_CAPABILITIES

    confirmed_names = {c.name for c in result.confirmed}
    absent_names = {a.name for a in result.absent}
    assert confirmed_names.isdisjoint(absent_names)
    assert confirmed_names | absent_names == set(_MOBILE_CAPABILITIES.keys())


# ---------------------------------------------------------------------
# Evidence ordering
# ---------------------------------------------------------------------

async def test_evidence_order_permissions_before_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Evidence within a confirmed capability lists permissions first,
    then intent actions, then manifest flags — the deterministic
    reading order documented in :func:`_evaluate_capability`."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_apk(
        monkeypatch,
        permissions=["android.permission.READ_PHONE_STATE"],
        receivers=["com.example.app.CallReceiver"],
        intent_filters={
            ("receiver", "com.example.app.CallReceiver"): {
                "action": ["android.intent.action.PHONE_STATE"],
                "category": [],
            },
        },
    )

    result = await _call_verify(str(apk))

    confirmed_by_name = {c.name: c for c in result.confirmed}
    cap = confirmed_by_name["phone_capabilities"]
    sources = [e.source for e in cap.evidence]
    # The permission evidence must appear before any intent_action
    # evidence within the same capability.
    perm_idx = sources.index("permission")
    action_idx = sources.index("intent_action")
    assert perm_idx < action_idx
