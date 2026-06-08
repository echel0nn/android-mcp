"""Tests for the YARA-over-decompiled-tree wrapper.

Covers the public ``yara_scan_dir`` handler, the bundled
``android_basic.yar`` ruleset, and the helpers it leans on. Tests
build a tiny fake "decompiled" tree on disk per case instead of
mocking yara — the library is pure Python from the caller's
perspective and the round-trip is cheap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


async def _call_scan(
    decompiled_dir: str,
    ruleset_path: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve the registered ``yara_scan_dir`` handler and call it.

    Mirrors the pattern other android-mcp tools follow: ``register``
    is the public entrypoint, so the test reaches the handler
    through it rather than poking at module internals.
    """
    from android_mcp.tools.yara_decompiled import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture yara_scan_dir"
    return await fn(decompiled_dir=decompiled_dir, ruleset_path=ruleset_path)


def _drop(tree: Path, rel: str, body: bytes | str) -> Path:
    """Write a file under ``tree/rel`` (creating dirs), return its path."""
    target = tree / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, str):
        target.write_text(body, encoding="utf-8")
    else:
        target.write_bytes(body)
    return target


# ---------------------------------------------------------------------
# Bundled ruleset sanity
# ---------------------------------------------------------------------

def test_bundled_default_ruleset_exists() -> None:
    """The bundled YARA ruleset must ship with the package."""
    from android_mcp.tools.yara_decompiled import _DEFAULT_RULESET

    assert _DEFAULT_RULESET.exists(), f"default ruleset missing at {_DEFAULT_RULESET}"
    assert _DEFAULT_RULESET.suffix == ".yar"


def test_bundled_default_ruleset_compiles() -> None:
    """The bundled ruleset must parse under the installed yara-python."""
    import yara

    from android_mcp.tools.yara_decompiled import _DEFAULT_RULESET

    # A SyntaxError here means the bundled .yar has drifted away from
    # the installed yara-python's grammar — block the build.
    yara.compile(filepath=str(_DEFAULT_RULESET))


# ---------------------------------------------------------------------
# Happy paths — one test per bundled rule bucket
# ---------------------------------------------------------------------

async def test_aws_access_key_is_caught(tmp_path: Path) -> None:
    """AWS access-key literals trigger the hardcoded-secrets rule."""
    _drop(tmp_path, "src/Config.java",
          'public class Config { static String KEY = "AKIA0123456789ABCDEF"; }')

    results = await _call_scan(str(tmp_path))

    aws_hits = [r for r in results if r["rule_name"] == "android_secret_aws_access_key"]
    assert len(aws_hits) == 1, f"expected one AWS hit, got {results}"
    hit = aws_hits[0]
    assert hit["file"].endswith("Config.java")
    assert "hardcoded_secrets" in hit["tags"]
    assert hit["meta"]["category"] == "hardcoded-secrets"
    assert hit["strings"], "expected at least one string match"
    s = hit["strings"][0]
    assert s["identifier"] == "$aws"
    assert isinstance(s["offset"], int)
    assert "AKIA0123456789ABCDEF" in s["data_preview"]


async def test_google_api_key_is_caught(tmp_path: Path) -> None:
    _drop(tmp_path, "Network.kt",
          'val GMAPS = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"')

    results = await _call_scan(str(tmp_path))

    assert any(r["rule_name"] == "android_secret_google_api_key" for r in results)


async def test_firebase_url_is_caught(tmp_path: Path) -> None:
    _drop(tmp_path, "res/values/strings.xml",
          '<string name="fb">https://myapp-default-rtdb.firebaseio.com/</string>')

    results = await _call_scan(str(tmp_path))

    assert any(r["rule_name"] == "android_secret_firebase_url" for r in results)


async def test_pem_private_key_block_is_caught(tmp_path: Path) -> None:
    _drop(tmp_path, "assets/key.pem",
          "-----BEGIN PRIVATE KEY-----\nMIIE...stuff\n-----END PRIVATE KEY-----\n")

    results = await _call_scan(str(tmp_path))

    assert any(r["rule_name"] == "android_secret_pem_private_key" for r in results)


async def test_jwt_token_literal_is_caught(tmp_path: Path) -> None:
    # The three-segment JWT pattern triggers the secret rule.
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    _drop(tmp_path, "TokenStore.java", f'String tok = "{jwt}";')

    results = await _call_scan(str(tmp_path))

    assert any(r["rule_name"] == "android_secret_jwt_token" for r in results)


async def test_debug_log_call_is_caught(tmp_path: Path) -> None:
    _drop(tmp_path, "Checkout.java",
          'class Checkout { void start() { Log.d(TAG, "begin"); } }')

    results = await _call_scan(str(tmp_path))

    debug_hits = [r for r in results if r["rule_name"] == "android_debug_log_call"]
    assert len(debug_hits) == 1
    assert "debug_flags" in debug_hits[0]["tags"]


async def test_unsafe_ecb_crypto_is_caught(tmp_path: Path) -> None:
    _drop(tmp_path, "Crypto.java",
          'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");')

    results = await _call_scan(str(tmp_path))

    ecb_hits = [r for r in results if r["rule_name"] == "android_unsafe_crypto_ecb"]
    assert len(ecb_hits) == 1
    assert "unsafe_crypto" in ecb_hits[0]["tags"]


async def test_md5_digest_is_caught(tmp_path: Path) -> None:
    _drop(tmp_path, "Hashing.java",
          'MessageDigest md = MessageDigest.getInstance("MD5");')

    results = await _call_scan(str(tmp_path))

    assert any(r["rule_name"] == "android_unsafe_crypto_legacy_digest" for r in results)


async def test_no_op_trust_manager_is_caught(tmp_path: Path) -> None:
    body = (
        "public class AcceptAll implements X509TrustManager {\n"
        "  public void checkServerTrusted(X509Certificate[] chain, String authType) { }\n"
        "}\n"
    )
    _drop(tmp_path, "AcceptAll.java", body)

    results = await _call_scan(str(tmp_path))

    assert any(r["rule_name"] == "android_unsafe_trust_manager" for r in results)


# ---------------------------------------------------------------------
# Negative paths
# ---------------------------------------------------------------------

async def test_clean_source_returns_empty(tmp_path: Path) -> None:
    """A Java source with no secrets / debug / crypto smell yields []."""
    _drop(tmp_path, "Empty.java",
          "public final class Empty { public Empty() {} }")

    assert await _call_scan(str(tmp_path)) == []


async def test_empty_directory_returns_empty(tmp_path: Path) -> None:
    assert await _call_scan(str(tmp_path)) == []


async def test_missing_directory_raises_filenotfound(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(FileNotFoundError):
        await _call_scan(str(missing))


async def test_file_instead_of_directory_raises_value_error(tmp_path: Path) -> None:
    not_a_dir = _drop(tmp_path, "a.txt", "hello")
    with pytest.raises(ValueError):
        await _call_scan(str(not_a_dir))


async def test_custom_ruleset_path_is_used(tmp_path: Path) -> None:
    """When ruleset_path is supplied, that file's rules apply, not the default."""
    rules = _drop(
        tmp_path,
        "custom.yar",
        'rule only_foo { strings: $f = "FOOBAR-CANARY" condition: $f }',
    )
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    # This literal would match the bundled AWS rule iff the bundled
    # set were active; with the custom rules it must NOT fire, and the
    # custom rule must catch its own canary.
    _drop(decoded, "Source.java",
          'String a = "AKIA0123456789ABCDEF"; String b = "FOOBAR-CANARY";')

    results = await _call_scan(str(decoded), ruleset_path=str(rules))

    names = sorted(r["rule_name"] for r in results)
    assert names == ["only_foo"], (
        f"expected only the custom rule to fire, got {names}"
    )


async def test_missing_ruleset_raises_filenotfound(tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    missing_rules = tmp_path / "no-such-ruleset.yar"
    with pytest.raises(FileNotFoundError):
        await _call_scan(str(decoded), ruleset_path=str(missing_rules))


async def test_malformed_ruleset_raises_value_error(tmp_path: Path) -> None:
    bad = _drop(tmp_path, "bad.yar", "this is not yara at all")
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    with pytest.raises(ValueError):
        await _call_scan(str(decoded), ruleset_path=str(bad))


# ---------------------------------------------------------------------
# Walk-time filters
# ---------------------------------------------------------------------

async def test_binary_extensions_are_skipped(tmp_path: Path) -> None:
    """A .png named like an AWS key literal must not produce a match."""
    _drop(tmp_path, "assets/icon.png",
          b'AKIA0123456789ABCDEF would match if scanned, but png is skipped')

    assert await _call_scan(str(tmp_path)) == []


async def test_dex_files_are_skipped(tmp_path: Path) -> None:
    _drop(tmp_path, "classes.dex",
          b'AKIA0123456789ABCDEF do not scan dex')

    assert await _call_scan(str(tmp_path)) == []


async def test_files_under_git_dir_skipped(tmp_path: Path) -> None:
    """``.git`` is build/vcs output, not auditable source."""
    _drop(tmp_path, ".git/secrets",
          'String x = "AKIA0123456789ABCDEF";')

    assert await _call_scan(str(tmp_path)) == []


async def test_files_under_build_dir_skipped(tmp_path: Path) -> None:
    _drop(tmp_path, "build/generated/Stuff.java",
          'String x = "AKIA0123456789ABCDEF";')

    assert await _call_scan(str(tmp_path)) == []


async def test_oversized_file_skipped(tmp_path: Path, monkeypatch) -> None:
    """Files above _FILE_SIZE_CAP are skipped to bound the scan."""
    import android_mcp.tools.yara_decompiled as mod

    # Shrink the cap to 100 bytes for this test; the source file
    # carrying the secret is ~120 bytes so the walk filter trips.
    monkeypatch.setattr(mod, "_FILE_SIZE_CAP", 100)
    big = "X" * 200 + 'String k = "AKIA0123456789ABCDEF";'
    _drop(tmp_path, "Big.java", big)

    assert await _call_scan(str(tmp_path)) == []


# ---------------------------------------------------------------------
# Response-shape contract
# ---------------------------------------------------------------------

async def test_response_shape_matches_acceptance(tmp_path: Path) -> None:
    """Every match dict has the five PRD-mandated top-level keys plus
    the documented per-string sub-shape."""
    _drop(tmp_path, "Hit.java",
          'class H { static String K = "AKIA0123456789ABCDEF"; }')

    results = await _call_scan(str(tmp_path))

    assert len(results) >= 1
    top = results[0]
    assert set(top.keys()) == {"rule_name", "file", "tags", "meta", "strings"}
    assert isinstance(top["rule_name"], str)
    assert isinstance(top["file"], str)
    assert isinstance(top["tags"], list)
    assert all(isinstance(t, str) for t in top["tags"])
    assert isinstance(top["meta"], dict)
    assert isinstance(top["strings"], list)
    assert top["strings"]
    sub = top["strings"][0]
    assert set(sub.keys()) == {"identifier", "offset", "data_preview"}
    assert isinstance(sub["identifier"], str)
    assert isinstance(sub["offset"], int)
    assert isinstance(sub["data_preview"], str)


async def test_data_preview_truncated_to_cap(tmp_path: Path, monkeypatch) -> None:
    """``_preview`` clamps to ``_PREVIEW_CAP`` bytes regardless of
    upstream string length."""
    import android_mcp.tools.yara_decompiled as mod

    monkeypatch.setattr(mod, "_PREVIEW_CAP", 8)
    _drop(tmp_path, "Hit.java",
          'static String K = "AKIA0123456789ABCDEF";')

    results = await _call_scan(str(tmp_path))

    assert results
    preview = results[0]["strings"][0]["data_preview"]
    # AKIA + 16 = 20 chars; truncated to 8.
    assert len(preview.encode("utf-8")) <= 8
    assert preview == "AKIA0123"


def test_preview_handles_non_bytes_gracefully() -> None:
    from android_mcp.tools.yara_decompiled import _preview

    assert _preview(b"hello") == "hello"
    assert _preview(bytearray(b"hi")) == "hi"
    # Non-utf-8 bytes get replacement chars rather than raising.
    out = _preview(b"\xff\xfe\xfd")
    assert isinstance(out, str)
    # Anything string-coercible flows through str().
    assert _preview(12345) == "12345"


def test_iter_scan_targets_respects_filters(tmp_path: Path) -> None:
    from android_mcp.tools.yara_decompiled import _iter_scan_targets

    _drop(tmp_path, "keep.java", "x")
    _drop(tmp_path, "icon.png", b"binary")
    _drop(tmp_path, ".git/HEAD", "ref")
    _drop(tmp_path, "build/out.java", "x")
    _drop(tmp_path, "subpkg/nested.kt", "x")

    rels = sorted(p.relative_to(tmp_path).as_posix() for p in _iter_scan_targets(tmp_path))
    assert rels == ["keep.java", "subpkg/nested.kt"]
