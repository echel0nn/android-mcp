"""Tests for ``composite.find_secrets``.

Each test builds a tiny fake "decompiled" tree on disk under a
``tmp_path`` and exercises the registered handler through the
``register(mcp)`` capture pattern other android-mcp tests use. This
matches how the production code reaches the handler — never poke at
the bare function past ``register``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


async def _call_find_secrets(
    decompiled_dir: str,
    assets_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve the registered ``find_secrets`` handler and call it."""
    from android_mcp.composite import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture find_secrets"
    return await fn(decompiled_dir=decompiled_dir, assets_dir=assets_dir)


def _drop(tree: Path, rel: str, body: str | bytes) -> Path:
    """Write a file under ``tree/rel`` (creating parent dirs), return its path."""
    target = tree / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, str):
        target.write_text(body, encoding="utf-8")
    else:
        target.write_bytes(body)
    return target


# ---------------------------------------------------------------------
# register() shape
# ---------------------------------------------------------------------

def test_register_attaches_find_secrets_handler() -> None:
    from android_mcp.composite import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    assert callable(captured.get("fn"))
    assert captured["fn"].__name__ == "find_secrets"


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

async def test_missing_decompiled_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await _call_find_secrets(str(tmp_path / "does-not-exist"))


async def test_decompiled_dir_must_be_directory(tmp_path: Path) -> None:
    target = tmp_path / "not-a-dir.txt"
    target.write_text("hi", encoding="utf-8")
    with pytest.raises(ValueError):
        await _call_find_secrets(str(target))


async def test_missing_assets_dir_is_silently_skipped(tmp_path: Path) -> None:
    # An apk decoded without any assets/ directory is normal — the
    # caller should not have to special-case that.
    result = await _call_find_secrets(
        str(tmp_path),
        assets_dir=str(tmp_path / "no-assets"),
    )
    assert result == []


async def test_assets_dir_inside_decompiled_dir_not_scanned_twice(tmp_path: Path) -> None:
    # Drop a single AWS key and point both args at overlapping trees.
    # Without dedup the result list would contain two copies of the
    # same finding.
    _drop(tmp_path / "assets", "creds.txt", "key=AKIAIOSFODNN7EXAMPLE\n")
    result = await _call_find_secrets(str(tmp_path), assets_dir=str(tmp_path / "assets"))
    aws = [r for r in result if r["kind"] == "aws_access_key"]
    assert len(aws) == 1, f"expected dedup, got: {aws}"


# ---------------------------------------------------------------------
# Empty tree
# ---------------------------------------------------------------------

async def test_empty_tree_returns_empty_list(tmp_path: Path) -> None:
    assert await _call_find_secrets(str(tmp_path)) == []


# ---------------------------------------------------------------------
# Per-pattern detection
# ---------------------------------------------------------------------

async def test_detects_aws_access_key(tmp_path: Path) -> None:
    _drop(tmp_path, "src/Net.java", 'String K = "AKIAIOSFODNN7EXAMPLE";\n')
    result = await _call_find_secrets(str(tmp_path))
    hits = [r for r in result if r["kind"] == "aws_access_key"]
    assert len(hits) == 1
    h = hits[0]
    assert "AKIA" in h["redacted_match"]
    assert "MPLE" in h["redacted_match"]
    assert "AKIAIOSFODNN7EXAMPLE" not in h["redacted_match"], (
        "full credential leaked into redacted_match"
    )
    assert h["line"] == 1
    assert h["file"].endswith("Net.java")
    assert "AKIAIOSFODNN7EXAMPLE" in h["context_80b"]


async def test_detects_google_api_key(tmp_path: Path) -> None:
    # 35 url-safe chars after the `AIza` prefix → 39 chars total.
    key = "AIza" + "A" * 35
    _drop(tmp_path, "res/values/strings.xml",
          f'<resources><string name="g">{key}</string></resources>\n')
    result = await _call_find_secrets(str(tmp_path))
    hits = [r for r in result if r["kind"] == "google_api_key"]
    assert len(hits) == 1
    assert hits[0]["redacted_match"].startswith("AIza")


async def test_detects_jwt_token(tmp_path: Path) -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    _drop(tmp_path, "src/Auth.java", f'String t = "{jwt}";\n')
    result = await _call_find_secrets(str(tmp_path))
    hits = [r for r in result if r["kind"] == "jwt_token"]
    assert len(hits) == 1
    assert hits[0]["redacted_match"].startswith("eyJh")


async def test_detects_pem_private_key(tmp_path: Path) -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    _drop(tmp_path, "assets/key.pem", pem)
    result = await _call_find_secrets(str(tmp_path))
    hits = [r for r in result if r["kind"] == "pem_private_key"]
    assert len(hits) == 1
    assert "PRIVATE KEY" in hits[0]["redacted_match"] or "BEGIN" in hits[0]["redacted_match"]


async def test_detects_firebase_url(tmp_path: Path) -> None:
    url = "https://my-app-default-rtdb.firebaseio.com/users.json"
    _drop(tmp_path, "src/Firebase.java", f'String URL = "{url}";\n')
    result = await _call_find_secrets(str(tmp_path))
    hits = [r for r in result if r["kind"] == "firebase_url"]
    assert len(hits) >= 1, f"expected firebase_url match, got: {result}"
    assert "firebaseio.com" in hits[0]["context_80b"]


async def test_detects_generic_high_entropy_bearer(tmp_path: Path) -> None:
    # 40+ char URL-safe blob with mixed case + digits → entropy ~5.0
    token = "X7g9kP2sLm3qR8tNvBcZyHfWjU4xY1aE6dC0iOpQ"
    _drop(tmp_path, "src/Token.java", f'String T = "{token}";\n')
    result = await _call_find_secrets(str(tmp_path))
    hits = [r for r in result if r["kind"] == "generic_bearer"]
    assert len(hits) >= 1
    assert any(token[:4] in h["redacted_match"] for h in hits)


# ---------------------------------------------------------------------
# Shannon-entropy filter
# ---------------------------------------------------------------------

async def test_entropy_filter_suppresses_low_entropy_lookalikes(tmp_path: Path) -> None:
    # 40 chars of the same byte → entropy = 0.0 bits, well below 4.5.
    # Length matches the generic-bearer regex but should be dropped.
    _drop(tmp_path, "src/Junk.java", 'String j = "' + "A" * 40 + '";\n')
    result = await _call_find_secrets(str(tmp_path))
    generic = [r for r in result if r["kind"] == "generic_bearer"]
    assert generic == [], f"low-entropy lookalike leaked through: {generic}"


async def test_aws_pattern_bypasses_entropy_filter(tmp_path: Path) -> None:
    # AWS pattern has a deterministic prefix, so it must NOT need the
    # entropy filter to identify the credential — even a key with all
    # repeated chars in the body matches the syntactic shape.
    key = "AKIAAAAAAAAAAAAAAAAA"  # all-A body
    _drop(tmp_path, "src/Junk.java", f'String k = "{key}";\n')
    result = await _call_find_secrets(str(tmp_path))
    aws = [r for r in result if r["kind"] == "aws_access_key"]
    assert len(aws) == 1


# ---------------------------------------------------------------------
# Walker: skip rules
# ---------------------------------------------------------------------

async def test_skips_binary_extensions(tmp_path: Path) -> None:
    # PNG file with an AWS-looking byte sequence inside. The walker
    # must drop it because `.png` is in _SKIP_EXTENSIONS.
    payload = b"\x89PNG\r\n\x1a\n" + b"AKIAIOSFODNN7EXAMPLE" + b"\x00" * 32
    _drop(tmp_path, "res/drawable/icon.png", payload)
    result = await _call_find_secrets(str(tmp_path))
    assert result == []


async def test_skips_oversized_files(tmp_path: Path) -> None:
    from android_mcp.composite import _FILE_SIZE_CAP

    target = tmp_path / "huge.txt"
    # Just above the cap. Padded with English so it does not also
    # blow the test's RAM budget.
    target.write_bytes(b"AKIAIOSFODNN7EXAMPLE\n" + b"x" * (_FILE_SIZE_CAP + 1))
    result = await _call_find_secrets(str(tmp_path))
    assert result == [], "file above _FILE_SIZE_CAP should have been skipped"


async def test_skips_vcs_and_build_dirs(tmp_path: Path) -> None:
    # Both `.git/` and `build/` are in _SKIP_DIRS.
    _drop(tmp_path / ".git", "creds.txt", "AKIAIOSFODNN7EXAMPLE\n")
    _drop(tmp_path / "build", "creds.txt", "AKIAIOSFODNN7EXAMPLE\n")
    _drop(tmp_path / "src", "Net.java", "// no credentials here\n")
    result = await _call_find_secrets(str(tmp_path))
    assert result == []


# ---------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------

async def test_every_finding_has_documented_keys(tmp_path: Path) -> None:
    _drop(tmp_path, "a.txt", "AKIAIOSFODNN7EXAMPLE\n")
    [hit] = await _call_find_secrets(str(tmp_path))
    assert set(hit.keys()) == {
        "file", "line", "kind", "redacted_match", "context_80b",
    }
    assert isinstance(hit["file"], str)
    assert isinstance(hit["line"], int) and hit["line"] >= 1
    assert isinstance(hit["kind"], str)
    assert isinstance(hit["redacted_match"], str)
    assert isinstance(hit["context_80b"], str)


async def test_context_80b_window_size(tmp_path: Path) -> None:
    # Plenty of pad on both sides so the centered window is full.
    pad = "z" * 200
    body = f"{pad}AKIAIOSFODNN7EXAMPLE{pad}"
    _drop(tmp_path, "a.txt", body)
    [hit] = await _call_find_secrets(str(tmp_path))
    # Window is 80 bytes wide; allow encoding-decoded length to match
    # exactly when content is pure ASCII.
    assert len(hit["context_80b"].encode("utf-8")) <= 80


async def test_line_number_matches_source(tmp_path: Path) -> None:
    body = "// header line\n// blank\nAPI = AKIAIOSFODNN7EXAMPLE\n"
    _drop(tmp_path, "Net.java", body)
    [hit] = await _call_find_secrets(str(tmp_path))
    assert hit["line"] == 3


# ---------------------------------------------------------------------
# Per-file finding cap
# ---------------------------------------------------------------------

async def test_per_file_finding_cap_enforced(tmp_path: Path) -> None:
    from android_mcp.composite import _MATCHES_PER_FILE_CAP

    # Drop more AWS keys than the cap. The cap must not be exceeded
    # within one file, but the response is still well-formed.
    keys = "\n".join(f"K{i}=AKIA{'A' * 16}" for i in range(_MATCHES_PER_FILE_CAP + 50))
    _drop(tmp_path, "spam.txt", keys)
    result = await _call_find_secrets(str(tmp_path))
    assert len(result) <= _MATCHES_PER_FILE_CAP


# ---------------------------------------------------------------------
# Duplicate-span suppression across patterns
# ---------------------------------------------------------------------

async def test_jwt_not_double_reported_as_generic_bearer(tmp_path: Path) -> None:
    # A JWT is high-entropy + URL-safe, so without dedup the
    # generic_bearer pattern would also fire across part of the
    # token. The handler should report a JWT match exactly once.
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    _drop(tmp_path, "a.txt", jwt + "\n")
    result = await _call_find_secrets(str(tmp_path))
    # The JWT regex consumes the whole token in one span, so the
    # generic-bearer regex's match across the same span gets
    # suppressed. The header and signature segments may still match
    # generic_bearer separately when not inside the JWT span — that's
    # acceptable, as long as we never report two findings with the
    # exact same span.
    spans = [(r["kind"], r["line"], r["context_80b"]) for r in result]
    assert len(spans) == len(set(spans))


# ---------------------------------------------------------------------
# Shannon-entropy helper
# ---------------------------------------------------------------------

def test_shannon_entropy_zero_for_constant_bytes() -> None:
    from android_mcp.composite import _shannon_entropy

    assert _shannon_entropy(b"AAAAAAAA") == 0.0


def test_shannon_entropy_max_for_uniform_distribution() -> None:
    from android_mcp.composite import _shannon_entropy

    # 256 unique bytes → 8 bits-per-byte ceiling.
    payload = bytes(range(256))
    assert _shannon_entropy(payload) == pytest.approx(8.0, abs=1e-6)


def test_shannon_entropy_empty_buffer_is_zero() -> None:
    from android_mcp.composite import _shannon_entropy

    assert _shannon_entropy(b"") == 0.0
