"""Tests for ``composite.classify_behavior``.

The handler walks androguard's ``Analysis`` graph for each
``(class, method)`` pair in :data:`composite._BEHAVIOR_CATEGORIES` and
projects the xrefs onto a per-category roll-up. Driving androguard
end-to-end would need a real APK on disk, which the test suite cannot
assume; instead these tests monkeypatch ``androguard.misc.AnalyzeAPK``
with a fake analysis object that returns hand-built ``MethodAnalysis``
doubles. The doubles only expose the surface the handler reads
(``get_xref_from``, ``class_name``, ``name``, ``is_external``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import pytest


# ---------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------

class _FakeMethodAnalysis:
    """Minimal stand-in for ``androguard.core.analysis.MethodAnalysis``.

    Carries a smali ``class_name`` + plain ``name`` + ``is_external``
    flag, and an ``xref_from`` list of ``(class_analysis, method,
    offset)`` tuples. The handler reads exactly these attributes.
    """

    def __init__(
        self,
        class_name: str,
        name: str,
        *,
        external: bool = False,
        xref_from: list[tuple[Any, "_FakeMethodAnalysis", int]] | None = None,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self._external = external
        self._xref_from = xref_from or []

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[Any, "_FakeMethodAnalysis", int]]:
        return list(self._xref_from)


class _FakeAnalysis:
    """Stand-in for ``Analysis`` exposing only ``find_methods``."""

    def __init__(self, methods: list[_FakeMethodAnalysis]) -> None:
        self._methods = methods

    def find_methods(
        self,
        classname: str = ".*",
        methodname: str = ".*",
        descriptor: str = ".*",
        accessflags: str = ".*",
        no_external: bool = False,
    ) -> Iterator[_FakeMethodAnalysis]:
        import re as _re

        cls_re = _re.compile(classname)
        meth_re = _re.compile(methodname)
        for m in self._methods:
            if not cls_re.search(m.class_name):
                continue
            if not meth_re.search(m.name):
                continue
            if no_external and m.is_external():
                continue
            yield m


class _FakeAPK:
    """Stand-in for ``androguard.core.apk.APK`` exposing only ``get_package``."""

    def __init__(self, package: str) -> None:
        self._package = package

    def get_package(self) -> str:
        return self._package


def _install_fake_analyze_apk(
    monkeypatch: pytest.MonkeyPatch,
    *,
    package: str = "com.example.app",
    methods: list[_FakeMethodAnalysis] | None = None,
) -> None:
    """Replace ``androguard.misc.AnalyzeAPK`` with a triple-returning fake."""
    fake = (_FakeAPK(package), [], _FakeAnalysis(methods or []))

    def _fake(_path: str, *_a: Any, **_kw: Any) -> tuple[Any, Any, Any]:
        return fake

    import androguard.misc as _amisc

    monkeypatch.setattr(_amisc, "AnalyzeAPK", _fake)


# ---------------------------------------------------------------------
# Handler capture (name-aware — composite.py registers >1 tool)
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


async def _call_classify(
    apk_path: str,
    workdir: str | None = None,
) -> dict[str, Any]:
    handlers = _capture_handlers()
    fn = handlers.get("classify_behavior")
    assert callable(fn), f"classify_behavior not registered (got: {sorted(handlers)})"
    return await fn(apk_path=apk_path, workdir=workdir)


def _write_dummy_apk(tmp_path: Path) -> Path:
    """Create a non-empty file that ``_sha256_file`` can read. Content is
    irrelevant because ``AnalyzeAPK`` is monkeypatched away."""
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"PK\x03\x04dummy-apk-content")
    return apk


# ---------------------------------------------------------------------
# register() shape
# ---------------------------------------------------------------------

def test_register_attaches_both_composite_handlers() -> None:
    handlers = _capture_handlers()
    assert "classify_behavior" in handlers
    assert "find_secrets" in handlers
    assert handlers["classify_behavior"].__name__ == "classify_behavior"


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

async def test_missing_apk_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await _call_classify(str(tmp_path / "does-not-exist.apk"))


async def test_directory_apk_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        await _call_classify(str(tmp_path))


# ---------------------------------------------------------------------
# Happy path — payload shape + writes report file
# ---------------------------------------------------------------------

async def test_empty_analysis_returns_full_category_skeleton(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the APK references no API in the table, every category
    still appears in the output with ``call_count=0`` and empty
    ``calls`` — consumers depend on that skeleton."""
    apk = _write_dummy_apk(tmp_path)
    _install_fake_analyze_apk(monkeypatch, package="com.empty.app", methods=[])

    result = await _call_classify(str(apk), workdir=str(tmp_path / "work"))

    assert result["package"] == "com.empty.app"
    assert isinstance(result["sha256_prefix"], str)
    assert len(result["sha256_prefix"]) == 16
    assert result["total_calls"] == 0

    from android_mcp.composite import _BEHAVIOR_CATEGORIES
    assert set(result["categories"].keys()) == set(_BEHAVIOR_CATEGORIES.keys())
    for cat in result["categories"].values():
        assert cat["call_count"] == 0
        assert cat["calls"] == []
        assert isinstance(cat["attack_techniques"], list)
        assert cat["attack_techniques"], "every category must declare >=1 ATT&CK ID"
        assert isinstance(cat["description"], str)


async def test_callers_are_collected_for_matching_apis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WebView.loadUrl xref from an internal application method
    should surface under the ``webview`` category with the dotted
    caller class + method name + offset."""
    apk = _write_dummy_apk(tmp_path)

    target = _FakeMethodAnalysis(
        class_name="Landroid/webkit/WebView;",
        name="loadUrl",
        external=True,
        xref_from=[
            (
                object(),
                _FakeMethodAnalysis(
                    class_name="Lcom/example/MainActivity;",
                    name="onCreate",
                    external=False,
                ),
                0x14,
            ),
        ],
    )
    _install_fake_analyze_apk(monkeypatch, methods=[target])

    result = await _call_classify(str(apk), workdir=str(tmp_path / "work"))

    webview = result["categories"]["webview"]
    assert webview["call_count"] == 1
    assert len(webview["calls"]) == 1
    call = webview["calls"][0]
    assert call["class"] == "android.webkit.WebView"
    assert call["method"] == "loadUrl"
    assert call["caller_count"] == 1
    assert call["callers"] == [
        {
            "caller_class": "com.example.MainActivity",
            "caller_method": "onCreate",
            "offset": 0x14,
        }
    ]
    assert webview["attack_techniques"] == ["T1437"]


async def test_external_callers_are_filtered_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Callers that are themselves external methods are noise — only
    application code (``is_external() == False``) should appear."""
    apk = _write_dummy_apk(tmp_path)

    target = _FakeMethodAnalysis(
        class_name="Ljava/lang/Runtime;",
        name="exec",
        external=True,
        xref_from=[
            (
                object(),
                _FakeMethodAnalysis(
                    class_name="Ljava/lang/Process;",
                    name="someBridge",
                    external=True,  # filtered out
                ),
                0x10,
            ),
            (
                object(),
                _FakeMethodAnalysis(
                    class_name="Lcom/example/Shell;",
                    name="run",
                    external=False,  # kept
                ),
                0x20,
            ),
        ],
    )
    _install_fake_analyze_apk(monkeypatch, methods=[target])

    result = await _call_classify(str(apk), workdir=str(tmp_path / "work"))
    native = result["categories"]["native_exec"]
    assert native["call_count"] == 1
    assert native["calls"][0]["callers"] == [
        {
            "caller_class": "com.example.Shell",
            "caller_method": "run",
            "offset": 0x20,
        }
    ]


async def test_duplicate_xrefs_are_deduped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same (caller_class, caller_method, offset) appearing twice in
    the xref list (e.g. across multiple target overrides) collapses
    into one entry."""
    apk = _write_dummy_apk(tmp_path)
    caller = _FakeMethodAnalysis(
        class_name="Lcom/example/Net;",
        name="fetch",
        external=False,
    )
    target = _FakeMethodAnalysis(
        class_name="Lokhttp3/OkHttpClient;",
        name="newCall",
        external=True,
        xref_from=[(object(), caller, 0x8), (object(), caller, 0x8)],
    )
    _install_fake_analyze_apk(monkeypatch, methods=[target])

    result = await _call_classify(str(apk), workdir=str(tmp_path / "work"))
    network = result["categories"]["network"]
    okhttp = next(
        c for c in network["calls"] if c["class"] == "okhttp3.OkHttpClient"
    )
    assert okhttp["caller_count"] == 1


async def test_report_file_is_written_and_matches_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The on-disk JSON report must equal the returned payload — VR's
    bridge layer reads the report file back without re-running
    androguard."""
    apk = _write_dummy_apk(tmp_path)
    target = _FakeMethodAnalysis(
        class_name="Landroid/telephony/TelephonyManager;",
        name="getDeviceId",
        external=True,
        xref_from=[
            (
                object(),
                _FakeMethodAnalysis(
                    class_name="Lcom/example/Id;",
                    name="probe",
                    external=False,
                ),
                0x0,
            ),
        ],
    )
    _install_fake_analyze_apk(monkeypatch, methods=[target])

    workdir = tmp_path / "work"
    result = await _call_classify(str(apk), workdir=str(workdir))

    report_path = Path(result["report_path"])
    assert report_path.exists()
    assert report_path.parent.name == result["sha256_prefix"]
    assert report_path.parent.parent == workdir.resolve()
    on_disk = json.loads(report_path.read_text(encoding="utf-8"))
    assert on_disk == result


async def test_caller_method_with_unparseable_offset_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """androguard occasionally returns non-int offsets in pathological
    xref shapes. The handler should record ``-1`` instead of crashing."""
    apk = _write_dummy_apk(tmp_path)
    target = _FakeMethodAnalysis(
        class_name="Ljavax/crypto/Cipher;",
        name="getInstance",
        external=True,
        xref_from=[
            (
                object(),
                _FakeMethodAnalysis(
                    class_name="Lcom/example/Crypt;",
                    name="setup",
                    external=False,
                ),
                "not-an-int",
            ),
        ],
    )
    _install_fake_analyze_apk(monkeypatch, methods=[target])

    result = await _call_classify(str(apk), workdir=str(tmp_path / "work"))
    crypto = result["categories"]["crypto"]
    assert crypto["call_count"] == 1
    assert crypto["calls"][0]["callers"][0]["offset"] == -1


# ---------------------------------------------------------------------
# Helper round-trips
# ---------------------------------------------------------------------

def test_dotted_to_smali_roundtrips() -> None:
    from android_mcp.composite import _dotted_to_smali, _smali_to_dotted

    cases = [
        "java.net.URL",
        "javax.crypto.Cipher",
        "android.provider.Settings$Secure",
        "com.example.app.MyClass",
    ]
    for dotted in cases:
        smali = _dotted_to_smali(dotted)
        assert smali.startswith("L") and smali.endswith(";")
        assert _smali_to_dotted(smali) == dotted


def test_smali_to_dotted_passes_through_non_class_descriptors() -> None:
    from android_mcp.composite import _smali_to_dotted

    # Array descriptors and primitives don't match the ``L...;`` shape.
    assert _smali_to_dotted("[B") == "[B"
    assert _smali_to_dotted("I") == "I"
    assert _smali_to_dotted("") == ""


def test_is_external_handles_missing_method() -> None:
    from android_mcp.composite import _is_external

    class _NoIsExternal:
        pass

    class _RaisesIsExternal:
        def is_external(self) -> bool:
            raise AttributeError("simulated androguard breakage")

    assert _is_external(_NoIsExternal()) is False
    assert _is_external(_RaisesIsExternal()) is False


def test_resolve_behavior_workdir_prefers_explicit_arg(tmp_path: Path) -> None:
    from android_mcp.composite import _resolve_behavior_workdir

    explicit = tmp_path / "custom-work"
    result = _resolve_behavior_workdir(str(explicit))
    assert result == explicit.resolve()


def test_resolve_behavior_workdir_falls_back_to_default() -> None:
    from android_mcp.composite import _DEFAULT_BEHAVIOR_WORKDIR, _resolve_behavior_workdir

    assert _resolve_behavior_workdir(None) == _DEFAULT_BEHAVIOR_WORKDIR
    assert _resolve_behavior_workdir("") == _DEFAULT_BEHAVIOR_WORKDIR


# ---------------------------------------------------------------------
# ATT&CK + category table integrity
# ---------------------------------------------------------------------

def test_every_category_has_attack_techniques_and_apis() -> None:
    """Defensive integrity check on the table itself — every category
    must declare at least one ATT&CK technique and one API tuple.
    Catches editing slips during table extensions."""
    from android_mcp.composite import _BEHAVIOR_CATEGORIES

    assert _BEHAVIOR_CATEGORIES, "category table must not be empty"
    for name, info in _BEHAVIOR_CATEGORIES.items():
        assert info["attack_techniques"], f"{name} has no ATT&CK techniques"
        assert info["apis"], f"{name} has no APIs"
        assert info["description"], f"{name} has no description"
        for entry in info["apis"]:
            assert isinstance(entry, tuple) and len(entry) == 2, (
                f"{name} API entry malformed: {entry!r}"
            )
            class_dotted, method = entry
            assert isinstance(class_dotted, str) and class_dotted
            assert isinstance(method, str) and method
