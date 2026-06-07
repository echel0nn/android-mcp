# android-mcp

Mobile security audit MCP server. Wraps the standard Android-security
toolchain (apktool, jadx, MobSF, androguard, frida, drozer, …) under
one MCP surface so an AI agent can drive APK audits without managing
tool installations or per-tool invocation syntax.

Sibling to:
- [audit-mcp](../audit-mcp/) — source-graph audits via Trailmark + Semble (port 18822)
- [ida-headless-mcp](../ida-headless-mcp-exp/) — binary analysis via Hex-Rays + miasm (port 18821)

This server lives on port **18823** by default. Same HTTP surface as
audit-mcp (`POST /tools/<name>`, `GET /tools`, `GET /tools/<name>/schema`)
so AILA's existing bridge layer maps cleanly.

## Status

**Phase 0 — scaffold only.** Four tools stubbed:

| tool | status | dep |
|---|---|---|
| `apktool_decode` | scaffold | OS `apktool` on PATH |
| `jadx_decompile` | scaffold | OS `jadx` on PATH |
| `mobsf_scan` | scaffold | running MobSF instance + `MOBSF_API_KEY` env |
| `androguard_summary` | scaffold | pip `androguard>=4.0`, `cryptography>=42` |

A future ralph loop (see `.run/ralph/android-mcp/` in the AILA repo)
fills out:

- frida helpers (gadget injection, hook templates, runtime trace)
- drozer wrapper (BadgeXposed-equivalent component-permission audit)
- qark (Quick Android Review Kit static rules)
- objection (frida wrapper for one-liner pen-test actions)
- needle (older iOS+Android pen-test framework; selectively useful)
- AndroBugs (specific bug-class scanner)
- yara-over-decompiled (custom rule scanning on jadx output)
- LIEF (native .so analysis inside APKs)
- apksigner / zipalign verification
- adb wrappers (dump system info, list installed apps, log capture)
- MARA (orchestration of multiple tools — pattern reference)
- The "verify capabilities" / "behavioral classification" /
  "compute risk score" composite tools that mirror audit-mcp's
  higher-level analysis layer

## Install (developer)

```bash
git clone <this repo> ../android-mcp
cd ../android-mcp
pip install -e ".[dev]"

# OS prerequisites — install one of these per tool:
# apktool   (https://apktool.org/)        — jar + launcher script on PATH
# jadx      (https://github.com/skylot/jadx/releases)  — bin on PATH
# MobSF     (https://mobsf.live/)         — `docker run -p 8000:8000 \
#                                            opensecurity/mobile-security-framework-mobsf`
#                                            then export MOBSF_API_KEY

# Run via stdio (for MCP clients):
python -m android_mcp

# Or HTTP (for AILA bridge):
python -m android_mcp --mode http --port 18823
```

## Wiring to AILA

Add to `~/.claude/.mcp.json`:

```json
{
  "mcpServers": {
    "android-mcp": {
      "command": "python",
      "args": ["-m", "android_mcp"],
      "env": {
        "PYTHONPATH": "C:/Users/THEDEVIL/Documents/android-mcp/src"
      }
    }
  }
}
```

For HTTP mode, register in AILA's MCP catalogue
(`src/aila/modules/vr/services/mcp_registry.py` style) with
`base_url=http://127.0.0.1:18823`.

## Why a separate MCP from audit-mcp

audit-mcp's tool surface is source-graph operations (read function,
search functions, callers, callees, semantic search). Mobile-security
tools have a totally different shape:

- Inputs: APK files, not source repos
- Outputs: structured static-analysis reports + decompiled trees
- Dependencies: heavy external binaries (Java/Kotlin runtimes,
  Docker containers, Python packages with C extensions)
- Lifecycle: scan-and-cache per APK, not "index once query many"

Forcing both into one server would couple unrelated upgrade cycles
(android-mcp evolves with the mobile-security toolchain;
audit-mcp evolves with Trailmark/Semble). Keeping them separate
mirrors the same split that exists between audit-mcp and ida-headless-mcp.

## Defaults

- Workdir: `~/.android-mcp/work/` (override via `ANDROID_MCP_WORKDIR`)
- Per-APK output: `<workdir>/<tool>-<sha256[:16]>/`
- HTTP port: 18823 (sibling to 18821 + 18822)

## License

AGPL-3.0-or-later — matches audit-mcp's license.
