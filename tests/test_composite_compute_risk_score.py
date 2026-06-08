"""Tests for ``composite.compute_risk_score``.

The handler aggregates pre-computed outputs from ``verify_capabilities``
(always derived in-process via androguard when not supplied), LIEF
native-lib summaries (also in-process when not supplied), and the
optional drozer + MobSF outputs (skipped + reported when absent).
The suite stays unit-level by passing every input as a hand-built
dict / typed model — only the lazy-invocation tests reach into
``_build_capability_profile`` / ``_summarize_native_libs`` and
monkeypatch them so the test never touches androguard or LIEF on a
real APK.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from android_mcp.composite import (
    AbsentCapability,
    CapabilityEvidence,
    ConfirmedCapability,
    MobileCapabilityProfile,
    RiskFactor,
    RiskScore,
    _RISK_CAP_EXPORTED_COMPONENT,
    _RISK_CAP_PROVIDER_INJECTION,
    _RISK_CAP_WORLD_WRITABLE,
    _RISK_SCORE_CAP,
    _RISK_W_BACKUP_ALLOWED,
    _RISK_W_CLEARTEXT,
    _RISK_W_DEBUGGABLE,
    _RISK_W_EXPORTED_COMPONENT,
    _RISK_W_MISSING_CANARY,
    _RISK_W_MISSING_NX,
    _RISK_W_MISSING_PIE,
    _RISK_W_MISSING_PINNING,
    _RISK_W_PROVIDER_INJECTION,
    _RISK_W_V1_ONLY_SIGNING,
    _RISK_W_WEAK_RELRO_NONE,
    _RISK_W_WEAK_RELRO_PARTIAL,
    _RISK_W_WORLD_WRITABLE,
)


# ---------------------------------------------------------------------
# Handler capture
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


async def _call_score(
    apk_path: str,
    **kwargs: Any,
) -> RiskScore:
    handlers = _capture_handlers()
    fn = handlers.get("compute_risk_score")
    assert callable(fn), (
        f"compute_risk_score not registered (got: {sorted(handlers)})"
    )
    return await fn(apk_path=apk_path, **kwargs)


def _write_dummy_apk(tmp_path: Path) -> Path:
    """File on disk so the path checks pass; content is irrelevant when the
    capability_profile and native_libs args are passed explicitly."""
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"PK\x03\x04dummy-apk-content")
    return apk


# ---------------------------------------------------------------------
# Profile builders — concise fixtures for the factor tests
# ---------------------------------------------------------------------

def _empty_profile(apk_path: Path, package: str = "com.example.app") -> MobileCapabilityProfile:
    """Profile with no confirmed capabilities — baseline for adding a factor at a time."""
    return MobileCapabilityProfile(
        package=package,
        apk_path=str(apk_path.resolve()),
        confirmed=[],
        absent=[],
        uncategorized=[],
    )


def _profile_with(
    apk_path: Path,
    *capabilities: tuple[str, list[CapabilityEvidence]],
    package: str = "com.example.app",
) -> MobileCapabilityProfile:
    """Profile with one or more confirmed capabilities + evidence rows."""
    return MobileCapabilityProfile(
        package=package,
        apk_path=str(apk_path.resolve()),
        confirmed=[
            ConfirmedCapability(name=name, description=name, evidence=evidence)
            for name, evidence in capabilities
        ],
        absent=[],
        uncategorized=[],
    )


def _lib(
    abi: str = "arm64-v8a",
    name: str = "libfoo.so",
    *,
    pie: bool = True,
    nx: bool = True,
    relro: str = "full",
    canary: bool = True,
    stripped: bool = True,
) -> dict[str, Any]:
    """One LIEF-shaped native-lib summary entry."""
    return {
        "abi": abi,
        "name": name,
        "header": {},
        "imports": [],
        "exports": [],
        "relocations": 0,
        "hardening": {
            "pie": pie,
            "nx": nx,
            "relro": relro,
            "canary": canary,
            "stripped": stripped,
        },
    }


def _by_factor(score: RiskScore) -> dict[str, RiskFactor]:
    return {f.factor: f for f in score.top_factors}


# ---------------------------------------------------------------------
# register() shape
# ---------------------------------------------------------------------

def test_register_attaches_compute_risk_score_handler() -> None:
    handlers = _capture_handlers()
    assert "compute_risk_score" in handlers, (
        f"compute_risk_score not registered (got: {sorted(handlers)})"
    )
    assert handlers["compute_risk_score"].__name__ == "compute_risk_score"


def test_register_attaches_all_four_composite_handlers() -> None:
    handlers = _capture_handlers()
    assert "find_secrets" in handlers
    assert "classify_behavior" in handlers
    assert "verify_capabilities" in handlers
    assert "compute_risk_score" in handlers


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

async def test_missing_apk_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await _call_score(str(tmp_path / "does-not-exist.apk"))


async def test_directory_apk_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        await _call_score(str(tmp_path))


# ---------------------------------------------------------------------
# Empty inputs — zero score, every optional tool in missing_inputs
# ---------------------------------------------------------------------

async def test_empty_inputs_score_zero(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
    )
    assert score.score == 0
    assert score.raw_total == 0
    assert score.top_factors == []
    assert sorted(score.missing_inputs) == ["drozer", "mobsf"]


async def test_apk_path_normalized_to_absolute(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
    )
    assert score.apk_path == str(apk.resolve())
    assert score.package == "com.example.app"


async def test_optional_inputs_populate_missing_inputs(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    # Provide drozer but NOT mobsf.
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        drozer_scan={"package": "com.example.app", "exported_components": {
            "activities": 0, "receivers": 0, "providers": 0, "services": 0,
            "is_debuggable": False,
        }, "finder_results": {"provider_injection": [], "activity_browsable": []}},
    )
    assert score.missing_inputs == ["mobsf"]


# ---------------------------------------------------------------------
# v1-only signing factor — single boolean signal
# ---------------------------------------------------------------------

async def test_v1_only_signing_contributes_fixed_weight(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("legacy_signing_scheme_only", [
            CapabilityEvidence(source="signing_scheme", detail="v1"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    factors = _by_factor(score)
    assert "v1_only_signing" in factors
    assert factors["v1_only_signing"].contribution == _RISK_W_V1_ONLY_SIGNING
    assert factors["v1_only_signing"].weight == _RISK_W_V1_ONLY_SIGNING
    assert score.score == _RISK_W_V1_ONLY_SIGNING


async def test_modern_signing_does_not_contribute(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("modern_signing_scheme", [
            CapabilityEvidence(source="signing_scheme", detail="v3"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    assert "v1_only_signing" not in _by_factor(score)
    assert score.score == 0


# ---------------------------------------------------------------------
# Exported-components factor — drozer-driven count + manifest fallback + cap
# ---------------------------------------------------------------------

async def test_exported_components_from_drozer_count(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    drozer = {
        "package": "com.example.app",
        "exported_components": {
            "activities": 1, "receivers": 0, "providers": 0, "services": 0,
            "is_debuggable": False,
        },
        "finder_results": {"provider_injection": [], "activity_browsable": []},
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        drozer_scan=drozer,
    )
    factors = _by_factor(score)
    assert factors["exported_components"].contribution == _RISK_W_EXPORTED_COMPONENT


async def test_exported_components_capped_at_30(tmp_path: Path) -> None:
    """7 components × 15pts each = 105 raw; cap of 30 must apply."""
    apk = _write_dummy_apk(tmp_path)
    drozer = {
        "package": "com.example.app",
        "exported_components": {
            "activities": 3, "receivers": 2, "providers": 1, "services": 1,
            "is_debuggable": False,
        },
        "finder_results": {"provider_injection": [], "activity_browsable": []},
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        drozer_scan=drozer,
    )
    factors = _by_factor(score)
    assert factors["exported_components"].contribution == _RISK_CAP_EXPORTED_COMPONENT
    # Cap must apply NOT a sum past the cap.
    assert factors["exported_components"].contribution < 7 * _RISK_W_EXPORTED_COMPONENT


async def test_exported_components_manifest_fallback(tmp_path: Path) -> None:
    """When drozer isn't supplied, fall back to manifest-derived exported list."""
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("exported_components", [
            CapabilityEvidence(
                source="exported_component", detail="activity:com.example.MainActivity",
            ),
            CapabilityEvidence(
                source="exported_component", detail="service:com.example.Sync",
            ),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    factors = _by_factor(score)
    assert factors["exported_components"].contribution == 2 * _RISK_W_EXPORTED_COMPONENT


# ---------------------------------------------------------------------
# Native-lib hardening factors
# ---------------------------------------------------------------------

async def test_missing_pie_per_lib(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    libs = [_lib(name="libsafe.so", pie=True), _lib(abi="armeabi-v7a", name="libbad.so", pie=False)]
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=libs,
    )
    factors = _by_factor(score)
    assert factors["missing_pie_per_native_lib"].contribution == _RISK_W_MISSING_PIE
    assert "armeabi-v7a/libbad.so" in factors["missing_pie_per_native_lib"].evidence


async def test_missing_nx_per_lib(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    libs = [_lib(name="libsafe.so", nx=True), _lib(name="libnoexec.so", nx=False)]
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=libs,
    )
    factors = _by_factor(score)
    assert factors["missing_nx_per_native_lib"].contribution == _RISK_W_MISSING_NX


async def test_weak_relro_partial_vs_none(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    libs = [
        _lib(name="libfull.so", relro="full"),
        _lib(name="libpartial.so", relro="partial"),
        _lib(name="libnone.so", relro="none"),
    ]
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=libs,
    )
    factors = _by_factor(score)
    expected = _RISK_W_WEAK_RELRO_PARTIAL + _RISK_W_WEAK_RELRO_NONE
    assert factors["weak_relro_per_native_lib"].contribution == expected
    # Weight reports the worst per-unit cost.
    assert factors["weak_relro_per_native_lib"].weight == _RISK_W_WEAK_RELRO_NONE


async def test_missing_stack_canary_per_lib(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    libs = [_lib(name="libsafe.so", canary=True), _lib(name="libunsafe.so", canary=False)]
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=libs,
    )
    factors = _by_factor(score)
    assert factors["missing_stack_canary_per_native_lib"].contribution == _RISK_W_MISSING_CANARY


async def test_native_libs_without_hardening_skipped(tmp_path: Path) -> None:
    """Extraction-failure entries have no ``hardening`` block; the factor walker skips them."""
    apk = _write_dummy_apk(tmp_path)
    libs = [{"abi": "arm64-v8a", "name": "libbroken.so", "error": "extract failed: OSError: ..."}]
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=libs,
    )
    # Score 0 — no other factors firing; no native-lib factor either.
    assert score.score == 0
    assert score.top_factors == []


# ---------------------------------------------------------------------
# Manifest-flag factors (debuggable / cleartext / backup)
# ---------------------------------------------------------------------

async def test_debuggable_build_contributes_fixed_weight(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("debuggable_build", [
            CapabilityEvidence(source="manifest_flag", detail="application.debuggable=true"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    factors = _by_factor(score)
    assert factors["debuggable_build"].contribution == _RISK_W_DEBUGGABLE
    assert "application.debuggable=true" in factors["debuggable_build"].evidence


async def test_cleartext_traffic_allowed_contributes(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("cleartext_traffic_allowed", [
            CapabilityEvidence(source="manifest_flag", detail="application.usesCleartextTraffic=true"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    factors = _by_factor(score)
    assert factors["cleartext_traffic_allowed"].contribution == _RISK_W_CLEARTEXT


async def test_backup_allowed_contributes(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("backup_allowed", [
            CapabilityEvidence(source="manifest_flag", detail="application.allowBackup=true"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    factors = _by_factor(score)
    assert factors["backup_allowed"].contribution == _RISK_W_BACKUP_ALLOWED


# ---------------------------------------------------------------------
# MobSF factors (world-writable + missing pinning)
# ---------------------------------------------------------------------

async def test_world_writable_from_code_analysis(tmp_path: Path) -> None:
    """MobSF native shape — code_analysis: {rule_id: {files: {file: line}}}"""
    apk = _write_dummy_apk(tmp_path)
    mobsf = {
        "code_analysis": {
            "android_world_writable_files": {
                "metadata": {"severity": "high"},
                "files": {"com/example/Foo.java": "42"},
            },
        },
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        mobsf_report=mobsf,
    )
    factors = _by_factor(score)
    assert factors["world_writable_files"].contribution == _RISK_W_WORLD_WRITABLE
    # Evidence carries the file location.
    assert any("com/example/Foo.java" in ev for ev in factors["world_writable_files"].evidence)


async def test_world_writable_capped(tmp_path: Path) -> None:
    """6 findings × 8pts each = 48 raw; cap of 24 must apply."""
    apk = _write_dummy_apk(tmp_path)
    mobsf = {
        "code_analysis": {
            f"world_writable_rule_{i}": {"files": {f"f{i}.java": "1"}}
            for i in range(6)
        },
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        mobsf_report=mobsf,
    )
    factors = _by_factor(score)
    assert factors["world_writable_files"].contribution == _RISK_CAP_WORLD_WRITABLE


async def test_world_writable_from_findings_list(tmp_path: Path) -> None:
    """Alternate MobSF shape — flat findings list."""
    apk = _write_dummy_apk(tmp_path)
    mobsf = {
        "findings": [
            {"rule_id": "android_world_writable", "file": "Foo.java", "line": 7},
        ],
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        mobsf_report=mobsf,
    )
    factors = _by_factor(score)
    assert factors["world_writable_files"].contribution == _RISK_W_WORLD_WRITABLE


async def test_missing_pinning_fires_once_per_report(tmp_path: Path) -> None:
    """Even with multiple pinning-related rules, the factor fires once."""
    apk = _write_dummy_apk(tmp_path)
    mobsf = {
        "code_analysis": {
            "android_certificate_pinning": {"files": {"Net.java": "1"}},
            "android_ssl_pinning_missing": {"files": {"Net.java": "5"}},
        },
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        mobsf_report=mobsf,
    )
    factors = _by_factor(score)
    assert factors["missing_certificate_pinning"].contribution == _RISK_W_MISSING_PINNING
    # Both matching rule ids land as evidence so the consumer sees both.
    assert len(factors["missing_certificate_pinning"].evidence) == 2


# ---------------------------------------------------------------------
# drozer provider-injection factor
# ---------------------------------------------------------------------

async def test_provider_injection_findings(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    drozer = {
        "package": "com.example.app",
        "exported_components": {
            "activities": 0, "receivers": 0, "providers": 0, "services": 0,
            "is_debuggable": False,
        },
        "finder_results": {
            "provider_injection": [
                {"uri": "content://com.example.app/users", "vector": "projection"},
                {"uri": "content://com.example.app/logs", "vector": "selection"},
            ],
            "activity_browsable": [],
        },
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        drozer_scan=drozer,
    )
    factors = _by_factor(score)
    assert factors["provider_injection_finding"].contribution == 2 * _RISK_W_PROVIDER_INJECTION


async def test_provider_injection_capped(tmp_path: Path) -> None:
    """5 findings × 12pts each = 60 raw; cap of 36 must apply."""
    apk = _write_dummy_apk(tmp_path)
    drozer = {
        "package": "com.example.app",
        "exported_components": {
            "activities": 0, "receivers": 0, "providers": 0, "services": 0,
            "is_debuggable": False,
        },
        "finder_results": {
            "provider_injection": [
                {"uri": f"content://com.example.app/r{i}", "vector": "projection"}
                for i in range(5)
            ],
            "activity_browsable": [],
        },
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        drozer_scan=drozer,
    )
    factors = _by_factor(score)
    assert factors["provider_injection_finding"].contribution == _RISK_CAP_PROVIDER_INJECTION


# ---------------------------------------------------------------------
# Top-factor sort + overall score cap
# ---------------------------------------------------------------------

async def test_top_factors_sorted_by_contribution_descending(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    # debuggable=12 + cleartext=7 + backup=4
    profile = _profile_with(
        apk,
        ("debuggable_build", [CapabilityEvidence(source="manifest_flag", detail="application.debuggable=true")]),
        ("cleartext_traffic_allowed", [CapabilityEvidence(source="manifest_flag", detail="application.usesCleartextTraffic=true")]),
        ("backup_allowed", [CapabilityEvidence(source="manifest_flag", detail="application.allowBackup=true")]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    contributions = [f.contribution for f in score.top_factors]
    assert contributions == sorted(contributions, reverse=True), (
        f"top_factors not sorted desc by contribution: {contributions}"
    )
    assert score.top_factors[0].factor == "debuggable_build"
    assert score.score == _RISK_W_DEBUGGABLE + _RISK_W_CLEARTEXT + _RISK_W_BACKUP_ALLOWED


async def test_score_caps_at_100(tmp_path: Path) -> None:
    """Maximum-bad-everything APK: raw_total may exceed 100; score caps at 100."""
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("legacy_signing_scheme_only", [CapabilityEvidence(source="signing_scheme", detail="v1")]),
        ("debuggable_build", [CapabilityEvidence(source="manifest_flag", detail="application.debuggable=true")]),
        ("cleartext_traffic_allowed", [CapabilityEvidence(source="manifest_flag", detail="application.usesCleartextTraffic=true")]),
        ("backup_allowed", [CapabilityEvidence(source="manifest_flag", detail="application.allowBackup=true")]),
    )
    libs = [
        _lib(name=f"libbad{i}.so", pie=False, nx=False, relro="none", canary=False)
        for i in range(5)
    ]
    drozer = {
        "package": "com.example.app",
        "exported_components": {
            "activities": 3, "receivers": 2, "providers": 1, "services": 1,
            "is_debuggable": True,
        },
        "finder_results": {
            "provider_injection": [
                {"uri": f"content://com.example.app/r{i}", "vector": "projection"}
                for i in range(5)
            ],
            "activity_browsable": [],
        },
    }
    mobsf = {
        "code_analysis": {
            f"world_writable_rule_{i}": {"files": {f"f{i}.java": "1"}}
            for i in range(6)
        },
    }
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=libs,
        drozer_scan=drozer,
        mobsf_report=mobsf,
    )
    assert score.score == _RISK_SCORE_CAP
    assert score.raw_total > _RISK_SCORE_CAP, (
        f"raw_total ({score.raw_total}) must exceed cap to validate clipping"
    )


# ---------------------------------------------------------------------
# Lazy invocation — capability_profile and native_libs derived in-process
# ---------------------------------------------------------------------

async def test_lazy_capability_profile_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_dummy_apk(tmp_path)
    called: dict[str, str] = {}

    def _fake_profile(path: str) -> MobileCapabilityProfile:
        called["path"] = path
        return MobileCapabilityProfile(
            package="com.lazy.app",
            apk_path=path,
            confirmed=[
                ConfirmedCapability(
                    name="debuggable_build",
                    description="debuggable_build",
                    evidence=[CapabilityEvidence(source="manifest_flag", detail="application.debuggable=true")],
                ),
            ],
            absent=[],
            uncategorized=[],
        )

    import android_mcp.composite as comp

    monkeypatch.setattr(comp, "_build_capability_profile", _fake_profile)
    monkeypatch.setattr(comp, "_summarize_native_libs", lambda _p: [])

    score = await _call_score(str(apk))

    assert called.get("path") == str(apk.resolve())
    assert score.package == "com.lazy.app"
    factors = _by_factor(score)
    assert factors["debuggable_build"].contribution == _RISK_W_DEBUGGABLE


async def test_lazy_native_libs_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    apk = _write_dummy_apk(tmp_path)
    called: dict[str, str] = {}

    def _fake_libs(path: str) -> list[dict[str, Any]]:
        called["path"] = path
        return [_lib(pie=False)]

    import android_mcp.composite as comp

    monkeypatch.setattr(
        comp, "_build_capability_profile", lambda p: _empty_profile(Path(p)),
    )
    monkeypatch.setattr(comp, "_summarize_native_libs", _fake_libs)

    score = await _call_score(str(apk))

    assert called.get("path") == str(apk.resolve())
    factors = _by_factor(score)
    assert factors["missing_pie_per_native_lib"].contribution == _RISK_W_MISSING_PIE


# ---------------------------------------------------------------------
# Schema sanity — RiskScore + RiskFactor round-trip through Pydantic
# ---------------------------------------------------------------------

async def test_risk_score_round_trips_through_model_dump(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("legacy_signing_scheme_only", [
            CapabilityEvidence(source="signing_scheme", detail="v1"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    dumped = score.model_dump()
    assert set(dumped.keys()) == {
        "score", "package", "apk_path", "raw_total", "top_factors", "missing_inputs",
    }
    re_validated = RiskScore.model_validate(dumped)
    assert re_validated.score == score.score
    assert re_validated.top_factors == score.top_factors


async def test_capability_profile_accepts_typed_model(tmp_path: Path) -> None:
    """Caller may pass the pre-validated ``MobileCapabilityProfile`` instead of a dict."""
    apk = _write_dummy_apk(tmp_path)
    profile = _profile_with(
        apk,
        ("legacy_signing_scheme_only", [
            CapabilityEvidence(source="signing_scheme", detail="v1"),
        ]),
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile,  # not .model_dump()
        native_libs=[],
    )
    assert score.score == _RISK_W_V1_ONLY_SIGNING


# ---------------------------------------------------------------------
# Absent capability profile — UncategorizedItem must not affect score
# ---------------------------------------------------------------------

async def test_uncategorized_and_absent_do_not_affect_score(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    profile = MobileCapabilityProfile(
        package="com.example.app",
        apk_path=str(apk.resolve()),
        confirmed=[],
        absent=[
            AbsentCapability(name="debuggable_build", description="debuggable_build"),
            AbsentCapability(name="legacy_signing_scheme_only", description="legacy_signing_scheme_only"),
        ],
        uncategorized=[],
    )
    score = await _call_score(
        str(apk),
        capability_profile=profile.model_dump(),
        native_libs=[],
    )
    assert score.score == 0
    assert score.top_factors == []


# ---------------------------------------------------------------------
# Drozer with zero-everything — exported_components factor is zero
# ---------------------------------------------------------------------

async def test_drozer_zero_counts_no_exported_components_factor(tmp_path: Path) -> None:
    apk = _write_dummy_apk(tmp_path)
    drozer = {
        "package": "com.example.app",
        "exported_components": {
            "activities": 0, "receivers": 0, "providers": 0, "services": 0,
            "is_debuggable": False,
        },
        "finder_results": {"provider_injection": [], "activity_browsable": []},
    }
    score = await _call_score(
        str(apk),
        capability_profile=_empty_profile(apk).model_dump(),
        native_libs=[],
        drozer_scan=drozer,
    )
    assert "exported_components" not in _by_factor(score)


# ---------------------------------------------------------------------
# Weight constants are non-zero — guards against accidental zero-out
# ---------------------------------------------------------------------

def test_risk_weight_constants_nonzero() -> None:
    for w in (
        _RISK_W_EXPORTED_COMPONENT,
        _RISK_W_V1_ONLY_SIGNING,
        _RISK_W_WORLD_WRITABLE,
        _RISK_W_MISSING_PINNING,
        _RISK_W_MISSING_PIE,
        _RISK_W_DEBUGGABLE,
        _RISK_W_CLEARTEXT,
        _RISK_W_BACKUP_ALLOWED,
        _RISK_W_MISSING_NX,
        _RISK_W_WEAK_RELRO_PARTIAL,
        _RISK_W_WEAK_RELRO_NONE,
        _RISK_W_MISSING_CANARY,
        _RISK_W_PROVIDER_INJECTION,
    ):
        assert w > 0, f"weight {w!r} must be > 0"


def test_risk_caps_at_least_one_unit() -> None:
    """Caps must be at least one unit's worth — otherwise the factor never fires."""
    assert _RISK_CAP_EXPORTED_COMPONENT >= _RISK_W_EXPORTED_COMPONENT
    assert _RISK_CAP_WORLD_WRITABLE >= _RISK_W_WORLD_WRITABLE
    assert _RISK_CAP_PROVIDER_INJECTION >= _RISK_W_PROVIDER_INJECTION
