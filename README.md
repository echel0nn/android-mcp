# android-mcp

Mobile-security audit MCP server. Wraps the standard Android-security
toolchain (apktool, jadx, MobSF, androguard, frida, drozer, qark,
objection, AndroBugs, LIEF, YARA, apksigner, adb) under one MCP
surface so a VR persona can drive an APK audit without managing
per-tool invocation syntax.

Sibling to:
- [audit-mcp](../audit-mcp/) — source-graph audits via Trailmark + Semble (port 18822)
- [ida-headless-mcp](../ida-headless-mcp-exp/) — binary analysis via Hex-Rays + miasm (port 18821)

This server lives on port **18823** by default. Same HTTP surface as
audit-mcp (`POST /tools/<name>`, `GET /tools`, `GET /tools/<name>/schema`)
so AILA's existing bridge layer attaches without code changes.

## Tool surface

Twenty handlers across thirteen per-tool wrapper modules, plus four
composite handlers under `composite.py`. Every handler is registered
through `server._register_all` and surfaces via `GET /tools` on port
`18823`.

Two status values describe each row:

- **ready** — the wrapper runs end-to-end once `pip install -e .` is
  done (plus the optional extras where called out). No additional
  OS-level install needed.
- **needs-binary** — the wrapper is shipped and tested, but it shells
  out to an external CLI or service the operator must install
  separately. The "OS / runtime prerequisite" column names what.

### Per-tool wrappers

| module | handler(s) | status | OS / runtime prerequisite |
|---|---|---|---|
| `tools/apktool.py` | `apktool_decode` | needs-binary | `apktool` on PATH (https://apktool.org/) |
| `tools/jadx.py` | `jadx_decompile` | needs-binary | `jadx` on PATH (https://github.com/skylot/jadx/releases) |
| `tools/mobsf_static.py` | `mobsf_scan` | needs-binary | running MobSF (`docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf`) + `MOBSF_API_KEY` env |
| `tools/androguard.py` | `androguard_summary` | ready | pip `androguard>=4.0` + `cryptography>=42` (already in project deps) |
| `tools/lief_so.py` | `analyze_native_libs` | ready | pip `lief>=0.16` (already in project deps) |
| `tools/yara_decompiled.py` | `yara_scan_dir` | ready | pip `yara-python>=4.5` (already in project deps); bundled ruleset at `data/rules/android_basic.yar` |
| `tools/apksigner.py` | `verify_apk_signing` | needs-binary | `apksigner` on PATH (Android SDK build-tools, `sdkmanager 'build-tools;34.0.0'`) |
| `tools/adb.py` | `adb_devices`, `adb_install`, `adb_uninstall`, `adb_logcat_capture`, `adb_dumpsys` | needs-binary | `adb` on PATH (Android platform-tools) |
| `tools/drozer.py` | `drozer_scan_apk` | needs-binary | `drozer` CLI on PATH + drozer agent running on the connected device |
| `tools/qark.py` | `qark_scan` | needs-binary | `pip install -e '.[scanners]'` lands the `qark` CLI |
| `tools/objection.py` | `objection_patch_apk`, `objection_explore` | needs-binary | `pip install -e '.[scanners]'` lands the `objection` CLI |
| `tools/androbugs.py` | `androbugs_scan` | needs-binary | AndroBugs Framework checkout + `ANDROBUGS_HOME` env (https://github.com/AndroBugs/AndroBugs_Framework); Python 2.7 on PATH unless the prebuilt `androbugs.exe` is used |
| `tools/frida_helpers.py` | `frida_list_running_devices`, `frida_dump_process_modules`, `frida_attach_and_trace_calls` | needs-binary | `pip install -e '.[dynamic]'` lands the `frida` Python client + `frida-server` running on the device |

### Composite handlers

The composite layer mirrors audit-mcp's higher-level analysis pattern.
VR personas call these directly instead of stitching per-tool wrappers
manually. Each handler imports its per-tool dependencies lazily so a
missing optional tool does not break the others.

| handler | status | inputs |
|---|---|---|
| `composite.find_secrets` | ready | decompiled tree on disk, optional assets dir; regex set covers AWS, Google, Firebase, PEM blocks, JWTs |
| `composite.classify_behavior` | ready | APK path; uses androguard's call-graph analysis; projects the dex API surface onto a 14-category ATT&CK-aligned table; writes `<workdir>/<sha[:16]>/behavior.json` |
| `composite.verify_capabilities` | ready | APK path; uses androguard's manifest + signing-cert parse; returns `MobileCapabilityProfile` with confirmed / absent / uncategorized buckets |
| `composite.compute_risk_score` | ready | APK path + optional `MobileCapabilityProfile`; aggregates verify_capabilities + LIEF + drozer + MobSF outputs into a 0-100 score with a sorted `top_factors` list |

## Install

```bash
git clone <this repo> ../android-mcp
cd ../android-mcp
pip install -e ".[dev,scanners,dynamic]"

# Minimal first-pass install of the OS prerequisites (lands the four
# "ready" composite handlers plus the apktool/jadx pair every other
# tool builds on):
#   apktool                     https://apktool.org/
#   jadx                        https://github.com/skylot/jadx/releases
#   Android SDK platform-tools  (ships adb + apksigner)

# Run via stdio (for MCP clients):
python -m android_mcp

# Or HTTP (for AILA bridge):
python -m android_mcp --mode http --port 18823
```

## Wiring to AILA — VR module

AILA's VR module routes APK targets through a five-stage ingestion
pipeline that drives this server's HTTP surface:
`apktool_decode` → `jadx_decompile` → `index_decompiled` →
`static_summary` → `mobsf_scan`. Stage names map to
`StageName.APK_DECODE`, `JADX_DECOMPILE`, `INDEX_DECOMPILED`,
`STATIC_SUMMARY`, `MOBSF_SCAN` in
`src/aila/modules/vr/contracts/target_stages.py`. The
`INDEX_DECOMPILED` stage hands the jadx Java tree off to audit-mcp
for graph indexing; the other four call android-mcp. `MOBSF_SCAN`
is gated on `MOBSF_API_KEY` presence and is pre-marked DONE-skipped
when the env var is absent. Server registration lives in
`src/aila/modules/vr/services/mcp_registry.py` under id
`android_mcp` (default URL `http://127.0.0.1:18823`, env-var
override `ANDROID_MCP_URL`).

## Wiring to AILA — Claude Code direct

Add to `~/.claude/.mcp.json` when Claude Code should talk to
android-mcp directly (outside the AILA VR module pipeline):

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

## Concurrency knobs

The HTTP transport routes every tool call through
`async_runtime.run_tool`, which adds per-tool semaphores, in-flight
dedup, wall-clock timeouts, and a resized anyio worker-thread pool.
Operators tune via env vars at server start time:

| env var | default | effect |
|---|---|---|
| `ANDROID_MCP_THREAD_POOL_LIMIT` | `64` | anyio worker-thread pool size; bump when concurrent sync tools (apktool, jadx) saturate the default |
| `ANDROID_MCP_TOOL_CAP_<TOOLNAME>` | see `DEFAULT_TOOL_CAPS` in `async_runtime.py` | per-tool concurrent-call cap. Heavy three: `apktool_decode=2`, `jadx_decompile=2`, `mobsf_scan=2`, `__default__=8` |
| `ANDROID_MCP_TIMEOUT_<TOOLNAME>` | see `DEFAULT_TOOL_TIMEOUTS_S` in `async_runtime.py` | per-tool wall-clock timeout in seconds. Heavy three: `apktool_decode=300`, `jadx_decompile=900`, `mobsf_scan=1800`, `__default__=120` |
| `ANDROID_MCP_WORKDIR` | `~/.android-mcp/work` | base dir for per-tool output (`apktool-<sha>/`, `jadx-<sha>/`, …) |

`<TOOLNAME>` is uppercased — for example
`ANDROID_MCP_TOOL_CAP_JADX_DECOMPILE=4`.

`GET /runtime` on the HTTP server returns live `{dedup: {inflight,
hits, misses}, semaphores: {<tool>: {cap, available}},
thread_pool_limit, tool_count, tools}` for live diagnostics. When
agents report "android-mcp is slow", check this endpoint first —
`available: 0` on a tool names the bottleneck; bump that tool's cap
via env.

## Why a separate MCP from audit-mcp

audit-mcp's tool surface is source-graph operations (read function,
search functions, callers, callees, semantic search). Mobile-security
tools have a different shape:

- Inputs: APK files, not source repos
- Outputs: structured static-analysis reports + decompiled trees
- Dependencies: heavy external binaries (Java/Kotlin runtimes,
  Docker containers, Python packages with C extensions)
- Lifecycle: scan-and-cache per APK, not "index once query many"

Forcing both into one server would couple unrelated upgrade cycles
(android-mcp evolves with the mobile-security toolchain; audit-mcp
evolves with Trailmark/Semble). Keeping them separate mirrors the
same split that already exists between audit-mcp and ida-headless-mcp.

## Defaults

- Workdir: `~/.android-mcp/work/` (override via `ANDROID_MCP_WORKDIR`)
- Per-tool output: `<workdir>/<tool>-<sha256[:16]>/`
- HTTP port: 18823 (sibling to 18821 + 18822)

## License

AGPL-3.0-or-later — matches audit-mcp's license.