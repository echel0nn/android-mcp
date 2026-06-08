"""Tests for the apksigner wrapper — verify APK signing schemes.

These tests run without `apksigner` installed: `subprocess.run` is
patched at the module level to return canned output. One smoke-test
exercises the real binary when it is on PATH, otherwise it skips
cleanly. The mock-based suite is the load-bearing one — it covers
the parser shape and the Janus heuristic without depending on a
particular SDK version.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _make_apk(tmp_path: Path) -> Path:
    """Make a placeholder file at .apk path. Content is irrelevant
    because the subprocess call is mocked — only the path-resolution
    branch in the handler reads it."""
    apk = tmp_path / "stub.apk"
    apk.write_bytes(b"PK\x03\x04")  # ZIP magic, enough to look real
    return apk


def _completed(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> MagicMock:
    """Build a stand-in for `subprocess.CompletedProcess`."""
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


async def _call_verify(apk_path: str) -> dict[str, Any]:
    """Resolve the registered `verify_apk_signing` handler and call it."""
    from android_mcp.tools.apksigner import register

    captured: dict[str, Any] = {}

    class _MCP:
        def tool(self):
            def deco(fn):
                captured["fn"] = fn
                return fn

            return deco

    register(_MCP())
    fn = captured.get("fn")
    assert callable(fn), "register did not capture verify_apk_signing"
    return await fn(apk_path=apk_path)


# Canned apksigner outputs. Each block was constructed to match the
# format Android SDK build-tools 30+ emits; older versions miss some
# fields (e.g. v3.1) but the parser tolerates that.

_V1_V2_V3_SINGLE_SIGNER = """\
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
Signer #1 certificate DN: CN=Android Debug, O=Android, C=US
Signer #1 certificate SHA-256 digest: 8a7c4cfcce04e6e8c4f5089b3a4e6f63bb87ed3a7c2e8b1d4f5e6a7b8c9d0e1f
Signer #1 certificate SHA-1 digest: aabbccddeeff00112233445566778899aabbccdd
Signer #1 certificate MD5 digest: aabbccddeeff00112233445566778899
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
"""

_V1_ONLY = """\
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
Number of signers: 1
Signer #1 certificate DN: CN=Vendor App, O=Old Vendor, C=US
Signer #1 certificate SHA-256 digest: abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1
"""

_V3_WITH_LINEAGE = """\
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate DN: CN=Current Signer, O=App, C=US
Signer #1 certificate SHA-256 digest: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
Lineage for signer #1 contains 2 certificates
Lineage signer #0 certificate DN: CN=Original Signer, O=App, C=US
Lineage signer #0 certificate SHA-256 digest: cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe
Lineage signer #0 key algorithm: RSA
Lineage signer #1 certificate DN: CN=Current Signer, O=App, C=US
Lineage signer #1 certificate SHA-256 digest: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
Lineage signer #1 key algorithm: RSA
"""

_TWO_SIGNERS = """\
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Number of signers: 2
Signer #1 certificate DN: CN=First, O=Org, C=US
Signer #1 certificate SHA-256 digest: aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111
Signer #2 certificate DN: CN=Second, O=Org, C=US
Signer #2 certificate SHA-256 digest: bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222
"""

_WITH_WARNINGS = """\
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Number of signers: 1
Signer #1 certificate DN: CN=Test, O=Test, C=US
Signer #1 certificate SHA-256 digest: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
WARNING: META-INF/CERT.SF indicates the file is signed by an unknown issuer
WARNING: APK Signature Scheme v3 stripping protection is not applied
"""

_DOES_NOT_VERIFY = """\
DOES NOT VERIFY
ERROR: META-INF/CERT.SF has an incorrect digest for AndroidManifest.xml
"""

_V3_1_PRESENT = """\
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): true
Number of signers: 1
Signer #1 certificate DN: CN=App, O=Co, C=US
Signer #1 certificate SHA-256 digest: feed00feed00feed00feed00feed00feed00feed00feed00feed00feed00feed
"""


async def test_v1_v2_v3_single_signer(tmp_path: Path) -> None:
    """Parser picks up every "true" scheme line and the signer block."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(stdout=_V1_V2_V3_SINGLE_SIGNER),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is True
    assert result["schemes"] == ["v1", "v2", "v3"]
    assert len(result["signers"]) == 1
    signer = result["signers"][0]
    assert signer["subject"] == "CN=Android Debug, O=Android, C=US"
    assert signer["sha256"].startswith("8a7c4cfc")
    assert signer["lineage_predecessors"] == []
    # No Janus warning because v2 and v3 are also present.
    assert all(
        "Janus" not in w and "CVE-2017-13156" not in w
        for w in result["warnings"]
    )


async def test_v1_only_emits_janus_warning(tmp_path: Path) -> None:
    """v1-only verified APK gets the synthesized Janus / CVE warning."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(stdout=_V1_ONLY),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is True
    assert result["schemes"] == ["v1"]
    janus = [w for w in result["warnings"] if "CVE-2017-13156" in w]
    assert len(janus) == 1, f"expected one Janus warning, got {result['warnings']}"
    assert "v1-only" in janus[0]


async def test_unverified_v1_does_not_get_janus_warning(tmp_path: Path) -> None:
    """The Janus warning only fires for verified APKs — an unverified
    v1-only APK is already broken; piling on with CVE labels would be
    noise."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(returncode=1, stdout=_V1_ONLY),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is False
    assert all("CVE-2017-13156" not in w for w in result["warnings"])


async def test_v3_lineage_drops_current_signer_from_predecessors(
    tmp_path: Path,
) -> None:
    """Lineage `predecessors` excludes the current top-level signer."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(stdout=_V3_WITH_LINEAGE),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is True
    signer = result["signers"][0]
    # Two lineage entries in the output, but the trailing one matches
    # the top-level signer's SHA-256 and gets dropped.
    assert len(signer["lineage_predecessors"]) == 1
    pred = signer["lineage_predecessors"][0]
    assert pred["subject"] == "CN=Original Signer, O=App, C=US"
    assert pred["sha256"].startswith("cafebabe")


async def test_two_signers_both_surface(tmp_path: Path) -> None:
    """Multi-signer APKs (rare but legal) yield one entry per signer."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(stdout=_TWO_SIGNERS),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is True
    assert len(result["signers"]) == 2
    subjects = [s["subject"] for s in result["signers"]]
    assert subjects == ["CN=First, O=Org, C=US", "CN=Second, O=Org, C=US"]


async def test_warnings_collected_from_stdout(tmp_path: Path) -> None:
    """`WARNING:` lines on stdout flow into the warnings list."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(stdout=_WITH_WARNINGS),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is True
    # Two WARNING lines in the canned output.
    apksigner_warnings = [w for w in result["warnings"] if w.startswith("WARNING:")]
    assert len(apksigner_warnings) == 2


async def test_errors_collected_from_stderr(tmp_path: Path) -> None:
    """`ERROR:` lines on stderr flow into warnings, returncode=1 → verified=False."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(
                returncode=1,
                stdout=_DOES_NOT_VERIFY,
                stderr="ERROR: signature missing in central directory\n",
            ),
        ),
    ):
        result = await _call_verify(str(apk))

    assert result["verified"] is False
    assert any(w.startswith("ERROR:") for w in result["warnings"])


async def test_v3_1_scheme_recognized(tmp_path: Path) -> None:
    """The version regex accepts decimal-suffixed scheme tokens."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            return_value=_completed(stdout=_V3_1_PRESENT),
        ),
    ):
        result = await _call_verify(str(apk))

    assert "v3.1" in result["schemes"]
    assert result["schemes"] == ["v2", "v3", "v3.1"]


async def test_missing_apksigner_raises_runtime_error(tmp_path: Path) -> None:
    """When `apksigner` is not on PATH the handler raises with an install hint."""
    apk = _make_apk(tmp_path)
    with patch("android_mcp.tools.apksigner.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="apksigner not on PATH"):
            await _call_verify(str(apk))


async def test_missing_apk_raises_filenotfound(tmp_path: Path) -> None:
    """Missing APK path is reported as FileNotFoundError, not silently swallowed."""
    nonexistent = tmp_path / "missing.apk"
    with patch(
        "android_mcp.tools.apksigner.shutil.which",
        return_value="/fake/apksigner",
    ):
        with pytest.raises(FileNotFoundError):
            await _call_verify(str(nonexistent))


async def test_directory_raises_value_error(tmp_path: Path) -> None:
    """A directory at the APK path is rejected with ValueError."""
    a_dir = tmp_path / "looks-like-apk"
    a_dir.mkdir()
    with patch(
        "android_mcp.tools.apksigner.shutil.which",
        return_value="/fake/apksigner",
    ):
        with pytest.raises(ValueError, match="not a file"):
            await _call_verify(str(a_dir))


async def test_subprocess_timeout_becomes_runtime_error(tmp_path: Path) -> None:
    """A child timeout is translated into RuntimeError with a clean message."""
    apk = _make_apk(tmp_path)
    with (
        patch(
            "android_mcp.tools.apksigner.shutil.which",
            return_value="/fake/apksigner",
        ),
        patch(
            "android_mcp.tools.apksigner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["apksigner"], timeout=60),
        ),
    ):
        with pytest.raises(RuntimeError, match="apksigner timed out"):
            await _call_verify(str(apk))


def test_parser_skips_blank_and_unknown_lines() -> None:
    """Parser ignores blank lines, version banners, and unrelated fields."""
    from android_mcp.tools.apksigner import _parse_apksigner_output

    noisy = """\

Some unrelated banner

Verified using v1 scheme (JAR signing): true
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 certificate DN: CN=Test
Signer #1 certificate SHA-256 digest: abcd

"""
    schemes, signers, warnings = _parse_apksigner_output(noisy, "")
    assert schemes == ["v1"]
    assert len(signers) == 1
    assert signers[0]["subject"] == "CN=Test"
    assert signers[0]["sha256"] == "abcd"
    assert warnings == []


def test_parser_handles_no_lineage_block() -> None:
    """A signer without a lineage block has `lineage_predecessors=[]`."""
    from android_mcp.tools.apksigner import _parse_apksigner_output

    schemes, signers, _ = _parse_apksigner_output(
        _V1_V2_V3_SINGLE_SIGNER, "",
    )
    assert signers[0]["lineage_predecessors"] == []


@pytest.mark.skipif(
    shutil.which("apksigner") is None,
    reason="apksigner not on PATH — skipping the real-binary smoke test",
)
async def test_real_apksigner_on_invalid_file_returns_unverified(
    tmp_path: Path,
) -> None:
    """Smoke test against the real binary: a non-APK file fails to
    verify, the handler returns `verified=False`, and the output
    captures apksigner's own error wording."""
    fake = tmp_path / "not-real.apk"
    fake.write_bytes(b"definitely not an apk")
    result = await _call_verify(str(fake))
    assert result["verified"] is False
    # The exact error text depends on apksigner version, but at least
    # one ERROR or WARNING row should surface for malformed input.
    assert result["warnings"], (
        "real apksigner should produce at least one diagnostic line on bad input"
    )
