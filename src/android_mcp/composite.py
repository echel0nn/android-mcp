"""Composite analysis — higher-level audit primitives.

Aggregates the per-tool wrappers under ``tools/`` into reasoning-friendly
shapes that mirror audit-mcp's composite layer. VR personas call these
directly instead of stitching the underlying per-tool wrappers
manually.

Implemented so far:

    find_secrets        — hardcoded credentials / API keys / PEM blocks /
                          JWTs / Firebase URLs across a decompiled tree
                          plus an optional extra assets dir.
    classify_behavior   — maps the API surface used by the dex bytecode
                          (via androguard's call-graph analysis) to
                          ATT&CK-aligned categories (network, crypto,
                          reflection, IPC, SMS, location, dynamic-code-
                          loading, native-exec, webview, …). Drops the
                          report at ``<workdir>/<sha[:16]>/behavior.json``.
    verify_capabilities — projects an APK onto a curated mobile-
                          capabilities catalogue (permissions, intent
                          actions, exported components, manifest flags,
                          signing schemes) and returns a typed
                          ``MobileCapabilityProfile`` with confirmed /
                          absent / uncategorized buckets. Mirrors
                          audit-mcp's ``verify_capabilities`` shape so
                          the VR persona prompt template translates
                          directly.
    compute_risk_score  — aggregates verify_capabilities + LIEF native-
                          lib hardening + (optional) drozer + MobSF
                          outputs into a 0-100 score with a documented
                          weighting table and a sorted ``top_factors``
                          list. Caps and per-factor weights live as
                          named module constants so the test suite
                          asserts against the same numbers the
                          handler docstring documents.

Each composite handler is registered via :func:`register` and follows
the same one-file-per-tool style as ``tools/<name>.py`` so the rest of
the server (``http_api._build_tool_index``, the FastMCP introspection
endpoints, AILA's bridge) treats it identically.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel, Field

_log = logging.getLogger(__name__)

# Context window emitted per finding. 80 bytes is the documented
# acceptance contract — wide enough to identify the surrounding code
# without bloating the response payload across thousands of findings.
_CONTEXT_BYTES = 80

# Shannon-entropy floor (bits-per-byte) for the entropy-gated patterns.
# Below this, a candidate match is dropped as an English-text or
# repeating-bytes lookalike. 4.5 is the conventional cutoff (truecrypto
# / detect-secrets / trufflehog all sit in [4.3, 5.0]).
_ENTROPY_MIN_BITS = 4.5

# Per-file size cap. Resource blobs above this are almost always
# binary assets the regex set will never match usefully (PNGs, OTF
# fonts, DEX files). 8 MiB matches yara_decompiled's cap.
_FILE_SIZE_CAP = 8 * 1024 * 1024

# Per-file finding cap. Pathological resource files (base64 dumps,
# minified bundles) can fire the generic-bearer rule thousands of
# times; capping keeps the response bounded.
_MATCHES_PER_FILE_CAP = 100

# Binary extensions that the regex set never matches usefully.
# Mirrors yara_decompiled's skip list — both modules walk the same
# kind of jadx/apktool output tree.
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".mp3", ".mp4", ".wav", ".ogg", ".m4a", ".aac",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".dex", ".odex", ".so", ".jar", ".aar", ".apk",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf",
    ".pyc", ".pyo",
    ".class",
})

# Directory names whose contents are machine output or VCS state — no
# point scanning them.
_SKIP_DIRS = frozenset({
    ".git", ".gradle", ".idea", "build", "node_modules", "__pycache__",
})

# Hardcoded-pattern table.
#
# Each entry is ``(kind, compiled_regex, needs_entropy_check,
# redact_as_marker)``. When ``needs_entropy_check`` is True the
# Shannon-entropy filter runs against the matched bytes, dropping
# <4.5 bits-per-byte patterns that accidentally fit the shape
# (English prose, repeating-char placeholders, lorem-ipsum filler).
# When ``redact_as_marker`` is True the redacted output keeps the
# full match verbatim — for purely structural indicators (PEM block
# headers, Firebase URLs) where the matched bytes are public-
# knowledge markers, not the credential themselves; the credential
# itself sits in the surrounding context, not in the match span.
#
# Patterns intentionally operate on bytes so the same regex applies
# uniformly across UTF-8 source files, ASCII XML, and Latin-1
# strings.xml resources without re-decoding per call.
_PATTERNS: tuple[tuple[str, re.Pattern[bytes], bool, bool], ...] = (
    # AWS Access Key ID — 16 char body after `AKIA` prefix; the
    # prefix itself rules out false-positive English text. Body is
    # the credential, so redact.
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}"), False, False),
    # Google API key — `AIza` + 35 URL-safe base64 chars. Documented
    # by Google's developer guides; used by Firebase, Maps, Places.
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), False, False),
    # JWT — three URL-safe base64 segments separated by dots.
    # `eyJ` is the deterministic start of any header that begins
    # with the `{"alg"` JSON, which all JWTs do.
    (
        "jwt_token",
        re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        False,
        False,
    ),
    # PEM private key block headers. The encrypted variant fires
    # too, since seeing one in an APK is a finding regardless. The
    # marker itself is structural — keep it visible so the
    # reviewer sees which variant (RSA / EC / ENCRYPTED) fired.
    (
        "pem_private_key",
        re.compile(
            rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"
        ),
        False,
        True,
    ),
    # Firebase Realtime Database / Hosting / App URL — the
    # presence of one is benign on its own, but it locates the
    # backend a reviewer needs to check for open ruleset. The URL
    # is a public-knowledge marker; keep it visible.
    (
        "firebase_url",
        re.compile(
            rb"https?://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app|firebaseapp\.com)/"
        ),
        False,
        True,
    ),
    # Generic high-entropy bearer / API key. Catches arbitrary
    # vendor tokens the four shape-anchored patterns miss. Gated
    # by the entropy filter — without it this fires on every
    # base64-padded image data URI and every long English run.
    (
        "generic_bearer",
        re.compile(rb"[A-Za-z0-9_\-+/=]{24,}"),
        True,
        False,
    ),
)

# Behavior-category map for ``classify_behavior``.
#
# Each category lists ATT&CK Mobile technique IDs the category maps to
# (https://attack.mitre.org/matrices/mobile/), a one-line description,
# and a tuple of ``(class_dotted, method)`` pairs that fingerprint the
# behaviour. The dotted form mirrors how the operator reads the API in
# Java/Kotlin source; the helpers below translate it to the smali
# signature androguard's ``find_methods`` expects.
#
# Curated to keep noise low: methods listed here are the canonical
# entry points the Android dev guides + a13e malware-analysis catalogues
# point at. Adding more APIs is mechanically safe — each entry is
# isolated; an unknown class/method simply produces zero callers.
_BEHAVIOR_CATEGORIES: dict[str, dict[str, Any]] = {
    "network": {
        "attack_techniques": ["T1437.001"],
        "description": "Application-layer network egress (HTTP/HTTPS).",
        "apis": (
            ("java.net.URL", "openConnection"),
            ("java.net.HttpURLConnection", "connect"),
            ("javax.net.ssl.HttpsURLConnection", "connect"),
            ("okhttp3.OkHttpClient", "newCall"),
            ("org.apache.http.client.HttpClient", "execute"),
        ),
    },
    "crypto": {
        "attack_techniques": ["T1521"],
        "description": "Cryptographic primitive use (Cipher / MessageDigest / KeyGenerator).",
        "apis": (
            ("javax.crypto.Cipher", "getInstance"),
            ("java.security.MessageDigest", "getInstance"),
            ("javax.crypto.KeyGenerator", "getInstance"),
            ("javax.crypto.Mac", "getInstance"),
        ),
    },
    "reflection": {
        "attack_techniques": ["T1623", "T1407"],
        "description": "Runtime reflection — Class.forName, Method.invoke, Field reads.",
        "apis": (
            ("java.lang.Class", "forName"),
            ("java.lang.reflect.Method", "invoke"),
            ("java.lang.reflect.Field", "get"),
        ),
    },
    "ipc": {
        "attack_techniques": ["T1437"],
        "description": "Cross-component IPC — content providers, intents, broadcasts.",
        "apis": (
            ("android.content.ContentResolver", "query"),
            ("android.content.Context", "startActivity"),
            ("android.content.Context", "sendBroadcast"),
            ("android.content.Context", "bindService"),
        ),
    },
    "sms": {
        "attack_techniques": ["T1582"],
        "description": "SMS send paths (premium-SMS abuse / 2FA exfil).",
        "apis": (
            ("android.telephony.SmsManager", "sendTextMessage"),
            ("android.telephony.SmsManager", "sendMultipartTextMessage"),
            ("android.telephony.SmsManager", "sendDataMessage"),
        ),
    },
    "location": {
        "attack_techniques": ["T1430"],
        "description": "Location tracking (LocationManager, fused-location).",
        "apis": (
            ("android.location.LocationManager", "getLastKnownLocation"),
            ("android.location.LocationManager", "requestLocationUpdates"),
            ("com.google.android.gms.location.FusedLocationProviderClient", "getLastLocation"),
        ),
    },
    "storage": {
        "attack_techniques": ["T1409"],
        "description": "Persistent storage writes — file streams + SQLite.",
        "apis": (
            ("java.io.FileOutputStream", "<init>"),
            ("android.database.sqlite.SQLiteDatabase", "openDatabase"),
            ("android.database.sqlite.SQLiteOpenHelper", "getWritableDatabase"),
        ),
    },
    "dynamic_loading": {
        "attack_techniques": ["T1407"],
        "description": "Runtime code loading (DexClassLoader, PathClassLoader, in-memory dex).",
        "apis": (
            ("dalvik.system.DexClassLoader", "<init>"),
            ("dalvik.system.PathClassLoader", "<init>"),
            ("dalvik.system.InMemoryDexClassLoader", "<init>"),
            ("dalvik.system.BaseDexClassLoader", "<init>"),
        ),
    },
    "native_exec": {
        "attack_techniques": ["T1623.001"],
        "description": "Shell / process spawning (Runtime.exec, ProcessBuilder).",
        "apis": (
            ("java.lang.Runtime", "exec"),
            ("java.lang.ProcessBuilder", "start"),
        ),
    },
    "webview": {
        "attack_techniques": ["T1437"],
        "description": "WebView bridge surface — URL loading + JS-interface exposure.",
        "apis": (
            ("android.webkit.WebView", "loadUrl"),
            ("android.webkit.WebView", "addJavascriptInterface"),
            ("android.webkit.WebView", "evaluateJavascript"),
            ("android.webkit.WebView", "loadData"),
            ("android.webkit.WebView", "loadDataWithBaseURL"),
        ),
    },
    "camera": {
        "attack_techniques": ["T1512"],
        "description": "Camera capture (legacy Camera API + CameraX bindings).",
        "apis": (
            ("android.hardware.Camera", "open"),
            ("android.hardware.camera2.CameraManager", "openCamera"),
        ),
    },
    "microphone": {
        "attack_techniques": ["T1429"],
        "description": "Audio capture (MediaRecorder + AudioRecord).",
        "apis": (
            ("android.media.MediaRecorder", "start"),
            ("android.media.AudioRecord", "startRecording"),
        ),
    },
    "device_info": {
        "attack_techniques": ["T1426"],
        "description": "Device-identifying reads (IMEI / SIM serial / subscriber id).",
        "apis": (
            ("android.telephony.TelephonyManager", "getDeviceId"),
            ("android.telephony.TelephonyManager", "getImei"),
            ("android.telephony.TelephonyManager", "getSubscriberId"),
            ("android.telephony.TelephonyManager", "getSimSerialNumber"),
            ("android.provider.Settings$Secure", "getString"),
        ),
    },
    "clipboard": {
        "attack_techniques": ["T1414"],
        "description": "Clipboard read/write — credential-harvesting + clipper malware.",
        "apis": (
            ("android.content.ClipboardManager", "getPrimaryClip"),
            ("android.content.ClipboardManager", "setPrimaryClip"),
            ("android.content.ClipboardManager", "addPrimaryClipChangedListener"),
        ),
    },
}

# Behavior-report workdir. Mirrors the apktool / jadx convention so
# the operator's three composite reports land under predictable
# adjacent paths (``<workdir>/apktool-<sha>/``, ``<workdir>/jadx-<sha>/``,
# ``<workdir>/<sha[:16]>/behavior.json``). Override via env var.
_DEFAULT_BEHAVIOR_WORKDIR = Path(
    os.environ.get("ANDROID_MCP_WORKDIR", "~/.android-mcp/work")
).expanduser()


# ---------------------------------------------------------------------
# verify_capabilities — typed return models
# ---------------------------------------------------------------------
#
# Mirror audit-mcp's ``verify_capabilities`` envelope so the VR persona
# prompt template translates directly. Each confirmed capability
# carries an ``evidence`` list — the exact permissions, intent
# actions, components, manifest flags, or signing schemes that
# triggered the verdict — so the persona can cite specific
# AndroidManifest.xml lines / data signals when proposing follow-up
# audit questions.


class CapabilityEvidence(BaseModel):
    """One piece of evidence supporting a confirmed capability.

    ``source`` is one of ``permission`` / ``intent_action`` /
    ``intent_filter`` / ``exported_component`` / ``manifest_flag`` /
    ``signing_scheme``. ``detail`` is the specific string: a
    permission FQN, an intent action, an intent-filter pair like
    ``VIEW+BROWSABLE@activity:com.foo.Bar``, a ``kind:name``
    component pair, a ``component.attr=value`` manifest flag, or
    an APK signing scheme label.
    """

    source: str
    detail: str


class ConfirmedCapability(BaseModel):
    """A capability the APK demonstrably exercises.

    ``evidence`` is the de-duplicated list of signals that confirm
    the capability. Empty list means the capability fired on a
    special-case rule (handled out-of-band) without contributing
    catalogue evidence — currently unreachable, kept as a guard
    so adding new specials never silently drops them.
    """

    name: str
    description: str
    evidence: list[CapabilityEvidence] = Field(default_factory=list)


class AbsentCapability(BaseModel):
    """A catalogue capability the APK does not exercise."""

    name: str
    description: str


class UncategorizedItem(BaseModel):
    """A permission or intent action the APK declares that the
    catalogue does not yet know about — the catalogue's growth list.
    """

    kind: str
    name: str


class MobileCapabilityProfile(BaseModel):
    """High-level capability snapshot for an APK.

    Shape mirrors audit-mcp's ``verify_capabilities`` for Windows
    binaries: ``confirmed`` (matched by at least one evidence
    source), ``absent`` (the catalogue capability that this APK
    does not exercise), and ``uncategorized`` (declared
    permissions or intent actions that don't map to any catalogue
    capability).
    """

    package: str | None
    apk_path: str
    confirmed: list[ConfirmedCapability]
    absent: list[AbsentCapability]
    uncategorized: list[UncategorizedItem]


# ---------------------------------------------------------------------
# compute_risk_score — typed return models
# ---------------------------------------------------------------------
#
# Each factor entry is a self-describing row the consumer can render
# without re-deriving the weight table from the docstring. ``weight``
# is the per-unit point value (the documented constant); ``contribution``
# is what that factor actually added to the score (capped where the
# factor has a cap, summed across multiple matches where it doesn't).
# Splitting the two means the consumer can see "v1-only signing: 10pt
# weight, 10pt contribution (single factor)" vs "exported components:
# 15pt weight, 30pt contribution (cap reached, 7 components)" without
# guessing which cap applies.


class RiskFactor(BaseModel):
    """One factor contributing to the overall risk score."""

    factor: str
    weight: int
    contribution: int
    evidence: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    """0-100 risk verdict for an APK with the contributing factor list.

    ``score`` is the capped total (max 100). ``raw_total`` is the same
    sum before the 100-point cap so the consumer can see when an APK
    is "off the chart" risky vs merely "everything is bad".
    ``top_factors`` lists every factor with non-zero contribution,
    sorted by contribution descending so ``top_factors[:5]`` is always
    the "five worst" view a UI would want. ``missing_inputs`` names
    the tool outputs the caller did not supply and the handler did not
    auto-derive, so the consumer knows the score is partial.
    """

    score: int
    package: str | None
    apk_path: str
    raw_total: int
    top_factors: list[RiskFactor]
    missing_inputs: list[str]


# ---------------------------------------------------------------------
# verify_capabilities — capabilities catalogue
# ---------------------------------------------------------------------
#
# Each capability lists:
#   description     — one-line statement of the capability
#   permissions     — tuple of FQN Android permissions; ANY match
#                     contributes evidence
#   intent_actions  — tuple of intent-filter action strings; ANY
#                     match across any component contributes
#                     evidence
#   manifest_flags  — tuple of ``(tag, attr, expected_value)``
#                     triples against the decoded manifest.
#                     ``expected_value`` of ``None`` means "any
#                     non-empty value counts" — useful for resource
#                     references like ``android:networkSecurityConfig``
#                     where the presence of the attribute is the
#                     signal, not the specific resource id.
#
# Three specials are handled out-of-band by the handler because they
# don't fit the flat (permission, action, flag) model:
#   exported_components            — any component reachable from
#                                    other apps (from androguard's
#                                    exported-component scan)
#   deep_linking                   — VIEW + BROWSABLE intent filter
#                                    pair on the same component
#   modern_signing_scheme /        — derived from the v1/v2/v3/v3.1
#     legacy_signing_scheme_only     signature schemes present on
#                                    the APK
#
# Adding a new permission-driven capability is a single dict entry
# here; no handler change required. Adding a new manifest-flag
# capability is one entry with the ``manifest_flags`` tuple
# populated; still no handler change.
_MOBILE_CAPABILITIES: dict[str, dict[str, Any]] = {
    "internet_access": {
        "description": "Sends or receives data over the internet.",
        "permissions": (
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.CHANGE_WIFI_STATE",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "location_access": {
        "description": "Reads device location (foreground or background).",
        "permissions": (
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "camera_access": {
        "description": "Captures images or video from the camera.",
        "permissions": (
            "android.permission.CAMERA",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "microphone_access": {
        "description": "Records audio from the microphone or output stream.",
        "permissions": (
            "android.permission.RECORD_AUDIO",
            "android.permission.CAPTURE_AUDIO_OUTPUT",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "external_storage": {
        "description": "Reads or writes shared/external storage and media.",
        "permissions": (
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "contacts_access": {
        "description": "Reads or writes the contacts database or account list.",
        "permissions": (
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "sms_capabilities": {
        "description": "Sends, receives, or reads SMS/MMS messages.",
        "permissions": (
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_WAP_PUSH",
        ),
        "intent_actions": (
            "android.provider.Telephony.SMS_RECEIVED",
            "android.provider.Telephony.SMS_DELIVER",
            "android.provider.Telephony.WAP_PUSH_RECEIVED",
        ),
        "manifest_flags": (),
    },
    "phone_capabilities": {
        "description": "Reads phone state, places calls, or processes outgoing calls.",
        "permissions": (
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
        ),
        "intent_actions": (
            "android.intent.action.PHONE_STATE",
            "android.intent.action.NEW_OUTGOING_CALL",
        ),
        "manifest_flags": (),
    },
    "biometric_auth": {
        "description": "Uses biometric authentication (fingerprint, face).",
        "permissions": (
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "background_execution": {
        "description": "Runs work outside of normal UI lifecycle (services, alarms, boot receivers).",
        "permissions": (
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.WAKE_LOCK",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.SCHEDULE_EXACT_ALARM",
            "android.permission.USE_EXACT_ALARM",
        ),
        "intent_actions": (
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.MY_PACKAGE_REPLACED",
        ),
        "manifest_flags": (),
    },
    "device_admin": {
        "description": "Acts as a device administrator (lock, wipe, password policy).",
        "permissions": (
            "android.permission.BIND_DEVICE_ADMIN",
        ),
        "intent_actions": (
            "android.app.action.DEVICE_ADMIN_ENABLED",
        ),
        "manifest_flags": (),
    },
    "accessibility_service": {
        "description": "Implements an accessibility service (can observe other apps' UI).",
        "permissions": (
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ),
        "intent_actions": (
            "android.accessibilityservice.AccessibilityService",
        ),
        "manifest_flags": (),
    },
    "package_management": {
        "description": "Installs, removes, or enumerates other installed packages.",
        "permissions": (
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.REQUEST_DELETE_PACKAGES",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.QUERY_ALL_PACKAGES",
        ),
        "intent_actions": (
            "android.intent.action.PACKAGE_ADDED",
            "android.intent.action.PACKAGE_REMOVED",
            "android.intent.action.PACKAGE_REPLACED",
        ),
        "manifest_flags": (),
    },
    "notifications": {
        "description": "Posts user-facing notifications or listens to others' notifications.",
        "permissions": (
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "bluetooth_access": {
        "description": "Discovers or pairs with Bluetooth devices.",
        "permissions": (
            "android.permission.BLUETOOTH",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_ADVERTISE",
        ),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "nfc_access": {
        "description": "Reads or writes NFC tags / runs HCE services.",
        "permissions": (
            "android.permission.NFC",
            "android.permission.NFC_PREFERRED_PAYMENT_INFO",
            "android.permission.NFC_TRANSACTION_EVENT",
        ),
        "intent_actions": (
            "android.nfc.action.NDEF_DISCOVERED",
            "android.nfc.action.TECH_DISCOVERED",
            "android.nfc.action.TAG_DISCOVERED",
        ),
        "manifest_flags": (),
    },
    "deep_linking": {
        "description": "Handles web/scheme deep links — entry point for external invocation.",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "exported_components": {
        "description": "Has at least one exported component reachable by other apps.",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "debuggable_build": {
        "description": "Built with android:debuggable=true (allows runtime introspection by other apps).",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (
            ("application", "debuggable", "true"),
        ),
    },
    "cleartext_traffic_allowed": {
        "description": "Allows cleartext HTTP traffic (android:usesCleartextTraffic=true).",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (
            ("application", "usesCleartextTraffic", "true"),
        ),
    },
    "backup_allowed": {
        "description": "App data is included in cloud/USB backups (android:allowBackup=true).",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (
            ("application", "allowBackup", "true"),
        ),
    },
    "custom_network_security_config": {
        "description": "Declares a custom networkSecurityConfig XML (per-domain TLS rules, pinning, cleartext exceptions).",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (
            ("application", "networkSecurityConfig", None),
        ),
    },
    "modern_signing_scheme": {
        "description": "Signed with APK Signature Scheme v2 / v3 / v3.1 — Janus-resistant on API >= 26.",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (),
    },
    "legacy_signing_scheme_only": {
        "description": "Signed ONLY with v1 (JAR signing) — vulnerable to Janus (CVE-2017-13156) on API <= 25.",
        "permissions": (),
        "intent_actions": (),
        "manifest_flags": (),
    },
}


# Pre-derived sets so the "is this declared permission/action known
# to any catalogue capability?" lookup is O(1) in the inner loop.
_CATALOGUED_PERMISSIONS: frozenset[str] = frozenset(
    perm
    for cap in _MOBILE_CAPABILITIES.values()
    for perm in cap["permissions"]
)
_CATALOGUED_INTENT_ACTIONS: frozenset[str] = frozenset(
    action
    for cap in _MOBILE_CAPABILITIES.values()
    for action in cap["intent_actions"]
)

# Deep-link intent-filter signature: action=VIEW + category=BROWSABLE
# must both appear on the same intent-filter for a deep link to
# fire — the system's Activity-resolution code requires BROWSABLE
# to dispatch a VIEW from an external context.
_DEEP_LINK_ACTION = "android.intent.action.VIEW"
_DEEP_LINK_CATEGORY = "android.intent.category.BROWSABLE"

# Component kinds androguard iterates when collecting intent filters
# and exported-component candidates.
_COMPONENT_KINDS: tuple[str, ...] = (
    "activity",
    "service",
    "receiver",
    "provider",
)

# APK signing-scheme labels exposed in evidence + the legacy/modern
# verdicts. v3.1 is grouped with the modern set.
_MODERN_SIGNING_SCHEMES: frozenset[str] = frozenset({"v2", "v3", "v3.1"})

# ---------------------------------------------------------------------
# compute_risk_score — weight table
# ---------------------------------------------------------------------
#
# Per-unit weights and caps. The docstring on the registered handler
# reproduces this table for the operator; keeping the numbers as
# named constants here makes the underlying scoring math readable
# and lets the tests reference the same values they assert against.
#
# Design: each factor weight reflects relative risk surface, not an
# absolute CVSS-style severity. ``debuggable_build`` is heavier than
# ``cleartext_traffic_allowed`` because a debuggable production
# build means any app on the device can attach a JDWP debugger and
# read arbitrary process memory — that's a wider hole than cleartext
# HTTP. Caps cover factors whose count can balloon (drozer can
# enumerate dozens of providers) so a single bad app doesn't
# saturate the 100-point ceiling with one factor.

_RISK_W_EXPORTED_COMPONENT = 15
_RISK_CAP_EXPORTED_COMPONENT = 30
_RISK_W_V1_ONLY_SIGNING = 10
_RISK_W_WORLD_WRITABLE = 8
_RISK_CAP_WORLD_WRITABLE = 24
_RISK_W_MISSING_PINNING = 6
_RISK_W_MISSING_PIE = 5
_RISK_W_DEBUGGABLE = 12
_RISK_W_CLEARTEXT = 7
_RISK_W_BACKUP_ALLOWED = 4
_RISK_W_MISSING_NX = 4
_RISK_W_WEAK_RELRO_PARTIAL = 1
_RISK_W_WEAK_RELRO_NONE = 3
_RISK_W_MISSING_CANARY = 2
_RISK_W_PROVIDER_INJECTION = 12
_RISK_CAP_PROVIDER_INJECTION = 36

# Overall 0-100 cap on the aggregated score. Raw totals above this
# clip to 100; the ``raw_total`` field on :class:`RiskScore` still
# carries the uncapped sum so the consumer sees the size of the
# overage.
_RISK_SCORE_CAP = 100

# Substrings the MobSF code_analysis / findings rule IDs may carry
# for the world-writable factor. MobSF's exact rule IDs drift
# across releases (``android_world_writable``,
# ``android_world_writable_files``, ``world_writable_files``) so
# we match by substring rather than by exact ID.
_MOBSF_WORLD_WRITABLE_TOKENS: tuple[str, ...] = (
    "world_writable",
    "world_readable",
)

# Substrings the MobSF code_analysis / findings rule IDs may carry
# for the missing-pinning factor. MobSF reports pinning absence as
# a finding (the rule "no certificate pinning detected" fires when
# the static-analysis pass walks the dex and finds no
# ``CertificatePinner``/``checkServerTrusted`` overrides). The
# substring set covers both the OWASP MASVS rule IDs and MobSF's
# native rule names.
_MOBSF_MISSING_PINNING_TOKENS: tuple[str, ...] = (
    "ssl_pinning",
    "certificate_pinning",
    "cert_pinning",
    "pinning_missing",
    "no_certificate_pinning",
    "no_ssl_pinning",
    "android_certificate_pinning",
)


def register(mcp: Any) -> None:
    @mcp.tool()
    async def find_secrets(
        decompiled_dir: str,
        assets_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        """Scan a decompiled APK tree (plus optional assets dir) for hardcoded secrets.

        Walks every text file under ``decompiled_dir`` and (when
        supplied and not already a sub-path) ``assets_dir``, applies
        the bundled hardcoded-pattern set, and projects each match
        onto a uniform ``{file, line, kind, redacted_match,
        context_80b}`` shape.

        Args:
            decompiled_dir: Root of a jadx or apktool output tree. The
                walker recurses into every subdirectory, including
                ``res/values/strings.xml``, so callers do not need to
                point at a specific subdirectory.
            assets_dir: Optional path to an extra assets directory.
                When the apktool ``assets/`` lives outside the
                ``decompiled_dir`` (e.g. apktool decoded resources
                separately from jadx's java output), pass it here.
                Skipped silently if it does not exist; ignored if it
                is already a sub-path of ``decompiled_dir`` so the
                same tree never scans twice.

        Returns:
            Flat list of ``{file, line, kind, redacted_match,
            context_80b}`` dicts. Empty list when nothing matched.
            ``file`` is the absolute path as a string. ``line`` is
            1-indexed. ``redacted_match`` shows enough of the match
            for the reviewer to recognise the secret without putting
            the full credential into a chat/log payload.

        Raises:
            FileNotFoundError: ``decompiled_dir`` does not exist.
            ValueError: ``decompiled_dir`` exists but is not a
                directory.
        """
        roots = _resolve_roots(decompiled_dir, assets_dir)
        results: list[dict[str, Any]] = []
        for root in roots:
            for file_path in _iter_scan_targets(root):
                results.extend(_scan_file(file_path))
        return results

    @mcp.tool()
    async def classify_behavior(
        apk_path: str,
        workdir: str | None = None,
    ) -> dict[str, Any]:
        """Map an APK's dex API surface to ATT&CK-aligned behavior categories.

        Runs ``androguard.misc.AnalyzeAPK`` against ``apk_path`` then,
        for each ``(class, method)`` pair in
        :data:`_BEHAVIOR_CATEGORIES`, walks ``Analysis.find_methods``'
        xref-from list to collect every internal caller. The result
        is a per-category roll-up of which ATT&CK techniques the APK
        exercises and which application methods reach them.

        Writes the same payload to
        ``<workdir>/<sha256[:16]>/behavior.json`` (override the workdir
        via the ``workdir`` arg, or the ``ANDROID_MCP_WORKDIR`` env
        var). The on-disk copy is what other tools and AILA's bridge
        layer read back without re-running androguard.

        Args:
            apk_path: Absolute (or ``~``-relative) path to the APK.
            workdir: Optional base dir for the behavior report. When
                ``None``, falls back to ``ANDROID_MCP_WORKDIR`` or
                ``~/.android-mcp/work``.

        Returns:
            ``{package, sha256_prefix, report_path, total_calls,
              categories: {<name>: {attack_techniques, description,
              calls: [{class, method, callers: [{caller_class,
              caller_method, offset}], caller_count}], call_count}}}``.

            Categories with zero callers are still listed (with empty
            ``calls`` / ``call_count=0``) so the consumer can show
            "absent" facts without re-deriving the schema.

        Raises:
            FileNotFoundError: ``apk_path`` does not exist.
            ValueError: ``apk_path`` exists but is not a file.
        """
        from androguard.misc import AnalyzeAPK  # local — keeps cold-start fast

        apk_p = Path(apk_path).expanduser().resolve()
        if not apk_p.exists():
            raise FileNotFoundError(f"apk not found: {apk_p}")
        if not apk_p.is_file():
            raise ValueError(f"apk_path is not a file: {apk_p}")

        sha = _sha256_file(apk_p)
        sha_prefix = sha[:16]
        out_dir = _resolve_behavior_workdir(workdir) / sha_prefix
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "behavior.json"

        apk_obj, _dex_list, dx = AnalyzeAPK(str(apk_p))

        categories: dict[str, dict[str, Any]] = {}
        total_calls = 0
        for cat_name, cat_info in _BEHAVIOR_CATEGORIES.items():
            calls = _collect_calls_for_category(dx, cat_info["apis"])
            call_count = sum(c["caller_count"] for c in calls)
            categories[cat_name] = {
                "attack_techniques": list(cat_info["attack_techniques"]),
                "description": cat_info["description"],
                "calls": calls,
                "call_count": call_count,
            }
            total_calls += call_count

        payload: dict[str, Any] = {
            "package": _safe_call(apk_obj.get_package),
            "sha256_prefix": sha_prefix,
            "report_path": str(report_path),
            "total_calls": total_calls,
            "categories": categories,
        }

        report_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return payload

    @mcp.tool()
    async def verify_capabilities(apk_path: str) -> MobileCapabilityProfile:
        """Project an APK onto the mobile-capabilities catalogue.

        Reads the APK via androguard (single in-process pass, no
        external binary required) and matches its declared
        permissions, intent-filter actions, exported components,
        application-level manifest flags, and APK signing schemes
        against :data:`_MOBILE_CAPABILITIES`. Returns a
        :class:`MobileCapabilityProfile` mirroring audit-mcp's
        ``verify_capabilities`` envelope so the VR persona prompt
        template translates directly between the two MCP surfaces.

        Three categories are derived out-of-band — they don't fit
        the flat (permission, action, flag) catalogue model:
        ``exported_components`` (any component reachable from other
        apps), ``deep_linking`` (a VIEW + BROWSABLE intent-filter
        pair on the same component), and the
        ``modern_signing_scheme`` / ``legacy_signing_scheme_only``
        verdicts (read from the v1/v2/v3/v3.1 signature blocks on
        the APK).

        Args:
            apk_path: Absolute (or ``~``-relative) path to the APK
                on the server filesystem.

        Returns:
            :class:`MobileCapabilityProfile` with three lists:

            * ``confirmed``: each capability the APK exercises,
              with a deduplicated ``evidence`` list naming the
              specific permission / action / component / manifest
              flag / signing scheme that triggered it.
            * ``absent``: each catalogue capability this APK does
              NOT exercise. Surfaced so the consumer can show
              "not present" facts without re-deriving the
              catalogue.
            * ``uncategorized``: permissions and intent actions
                the APK declares that no catalogue capability
                knows about — the catalogue's growth list.

        Raises:
            FileNotFoundError: ``apk_path`` does not exist.
            ValueError: ``apk_path`` exists but is not a file.
        Notes:
            The body of this handler lives in
            :func:`_build_capability_profile` so ``compute_risk_score``
            can reuse the same APK → profile derivation without
            round-tripping through the FastMCP closure.
        """
        return _build_capability_profile(apk_path)

    @mcp.tool()
    async def compute_risk_score(
        apk_path: str,
        capability_profile: dict[str, Any] | None = None,
        native_libs: list[dict[str, Any]] | None = None,
        drozer_scan: dict[str, Any] | None = None,
        mobsf_report: dict[str, Any] | None = None,
    ) -> RiskScore:
        """Compute a 0-100 risk score for an APK with contributing factors.

        Aggregates signals from the per-tool wrappers + verify_capabilities
        into a single capped score that the VR personas can read at a
        glance. Each factor has a per-unit weight and (where the count
        can balloon) a cap. The final score is the sum of contributions
        capped at 100; the uncapped sum lives on
        :class:`RiskScore.raw_total` so the consumer can see when an APK
        is way past the cap.

        Weighting table (these are also the named constants
        ``_RISK_W_*`` / ``_RISK_CAP_*`` in this module):

        ====================================  ======  =====
        Factor                                 Unit    Cap
        ====================================  ======  =====
        exported_components                     15      30
        v1_only_signing                         10       —
        world_writable_files                     8      24
        missing_certificate_pinning              6       —
        missing_pie_per_native_lib               5       —
        debuggable_build                        12       —
        cleartext_traffic_allowed                7       —
        backup_allowed                           4       —
        missing_nx_per_native_lib                4       —
        weak_relro_per_native_lib (partial=1,
          none=3)                                1/3     —
        missing_stack_canary_per_native_lib      2       —
        provider_injection_finding              12      36
        ====================================  ======  =====

        Final score capped at 100.

        Lazy invocation: when ``capability_profile`` or ``native_libs``
        is ``None`` the handler derives them on the fly via androguard
        / LIEF (both pure-Python, no external binaries). The
        ``drozer_scan`` and ``mobsf_report`` inputs are never auto-
        derived because they need a running drozer agent + a MobSF
        server respectively; if absent, the matching factors are
        skipped and the tool names land in ``missing_inputs`` so the
        consumer knows the score is partial.

        Args:
            apk_path: Absolute (or ``~``-relative) path to the APK on
                the server filesystem.
            capability_profile: Optional pre-computed
                ``MobileCapabilityProfile`` (as a dict, the
                JSON-serialised form returned by
                ``verify_capabilities``). When ``None`` the handler
                derives one in-process via androguard.
            native_libs: Optional pre-computed
                ``analyze_native_libs`` output (list of per-``.so``
                dicts). When ``None`` the handler walks the APK with
                LIEF in-process.
            drozer_scan: Optional pre-computed
                ``drozer_scan_apk`` output. Skipped factor when None.
            mobsf_report: Optional pre-computed ``mobsf_scan``
                output. Skipped factors when None.

        Returns:
            :class:`RiskScore` with ``score`` (0-100), ``raw_total``
            (uncapped sum), ``top_factors`` (sorted by contribution
            descending; only non-zero contributors), and
            ``missing_inputs`` (tool names whose absence reduced the
            score's coverage).

        Raises:
            FileNotFoundError: ``apk_path`` does not exist.
            ValueError: ``apk_path`` exists but is not a file.
        """
        apk_p = Path(apk_path).expanduser().resolve()
        if not apk_p.exists():
            raise FileNotFoundError(f"apk not found: {apk_p}")
        if not apk_p.is_file():
            raise ValueError(f"apk_path is not a file: {apk_p}")

        # Normalize the always-available inputs. capability_profile
        # accepts the JSON-serialised dict or a pre-validated
        # MobileCapabilityProfile; either way we end up holding the
        # typed model so factor evaluators have predictable shape.
        if capability_profile is None:
            profile = _build_capability_profile(str(apk_p))
        elif isinstance(capability_profile, MobileCapabilityProfile):
            profile = capability_profile
        else:
            profile = MobileCapabilityProfile.model_validate(capability_profile)

        if native_libs is None:
            native_libs_list = _summarize_native_libs(str(apk_p))
        else:
            native_libs_list = list(native_libs)

        missing_inputs: list[str] = []
        if drozer_scan is None:
            missing_inputs.append("drozer")
        if mobsf_report is None:
            missing_inputs.append("mobsf")

        confirmed_names = {c.name for c in profile.confirmed}

        factors: list[RiskFactor] = []
        factors.append(_factor_exported_components(profile, drozer_scan))
        factors.append(_factor_v1_only_signing(confirmed_names))
        factors.append(_factor_world_writable(mobsf_report))
        factors.append(_factor_missing_pinning(mobsf_report))
        factors.append(_factor_missing_pie(native_libs_list))
        factors.append(_factor_debuggable(confirmed_names, profile))
        factors.append(_factor_cleartext_traffic(confirmed_names, profile))
        factors.append(_factor_backup_allowed(confirmed_names, profile))
        factors.append(_factor_missing_nx(native_libs_list))
        factors.append(_factor_weak_relro(native_libs_list))
        factors.append(_factor_missing_stack_canary(native_libs_list))
        factors.append(_factor_provider_injection(drozer_scan))

        raw_total = sum(f.contribution for f in factors)
        score = min(raw_total, _RISK_SCORE_CAP)

        # Surface every non-zero contributor sorted by contribution
        # desc. Stable sort by ``factor`` name on ties so two equal
        # contributions render in a deterministic order across calls.
        top_factors = sorted(
            (f for f in factors if f.contribution > 0),
            key=lambda f: (-f.contribution, f.factor),
        )

        return RiskScore(
            score=score,
            package=profile.package,
            apk_path=str(apk_p),
            raw_total=raw_total,
            top_factors=top_factors,
            missing_inputs=missing_inputs,
        )


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _resolve_roots(decompiled_dir: str, assets_dir: str | None) -> list[Path]:
    """Resolve the two input paths into a deduped list of root dirs to scan.

    ``decompiled_dir`` is required and validated. ``assets_dir`` is
    optional: it is included only when it exists, is a directory, is
    not equal to ``decompiled_dir``, and is not a sub-path of
    ``decompiled_dir`` (avoids double-scanning when the operator
    points both arguments at the same tree).
    """
    d = Path(decompiled_dir).expanduser().resolve()
    if not d.exists():
        raise FileNotFoundError(f"decompiled_dir not found: {d}")
    if not d.is_dir():
        raise ValueError(f"decompiled_dir is not a directory: {d}")
    out: list[Path] = [d]

    if assets_dir:
        a = Path(assets_dir).expanduser().resolve()
        if not a.exists():
            _log.debug("assets_dir does not exist, skipping: %s", a)
        elif not a.is_dir():
            _log.debug("assets_dir is not a directory, skipping: %s", a)
        elif a == d or _is_subpath(a, d):
            _log.debug("assets_dir is already inside decompiled_dir, skipping: %s", a)
        else:
            out.append(a)

    return out


def _is_subpath(child: Path, parent: Path) -> bool:
    """True when ``child`` is at or below ``parent`` in the filesystem tree."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _iter_scan_targets(root: Path) -> Iterator[Path]:
    """Yield files under ``root`` worth feeding to the regex set.

    Filters applied (cheapest first):

    1. skip non-files (directories, symlinks to dirs)
    2. skip files whose extension is in ``_SKIP_EXTENSIONS``
    3. skip files inside any ``_SKIP_DIRS`` directory at any depth
    4. skip files larger than ``_FILE_SIZE_CAP``
    """
    skip_dirs = _SKIP_DIRS
    skip_exts = _SKIP_EXTENSIONS
    size_cap = _FILE_SIZE_CAP
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in skip_exts:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > size_cap:
                continue
        except OSError:
            continue
        yield path


def _scan_file(path: Path) -> list[dict[str, Any]]:
    """Apply every pattern to ``path``'s bytes and return projected findings.

    Reads the file once as bytes, runs each compiled regex via
    ``finditer``, and projects each match onto the documented
    response dict. Entropy-gated patterns drop matches whose
    Shannon entropy falls below ``_ENTROPY_MIN_BITS``.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        _log.debug("failed to read %s: %s", path, exc)
        return []

    out: list[dict[str, Any]] = []
    seen_spans: set[tuple[int, int]] = set()
    for kind, pattern, needs_entropy, redact_as_marker in _PATTERNS:
        for m in pattern.finditer(data):
            if len(out) >= _MATCHES_PER_FILE_CAP:
                return out
            span = m.span()
            # Suppress duplicate spans across patterns — a JWT will
            # often also match the generic-bearer pattern; report it
            # once under the more specific kind (which always runs
            # first in ``_PATTERNS``).
            if span in seen_spans:
                continue
            matched = m.group(0)
            if needs_entropy and _shannon_entropy(matched) < _ENTROPY_MIN_BITS:
                continue
            seen_spans.add(span)
            out.append({
                "file": str(path),
                "line": _line_at_offset(data, span[0]),
                "kind": kind,
                "redacted_match": _redact(matched, as_marker=redact_as_marker),
                "context_80b": _context(data, span[0], span[1]),
            })
    return out


def _line_at_offset(data: bytes, offset: int) -> int:
    """1-indexed line number of byte ``offset`` within ``data``."""
    return data.count(b"\n", 0, offset) + 1


def _context(data: bytes, start: int, end: int) -> str:
    """Extract ``_CONTEXT_BYTES`` of context around a match span.

    Centers the window on the match: half the leftover budget before
    the match, half after, clipped at the file boundaries. The match
    itself is included verbatim in the window (not redacted) so a
    reviewer can see the surrounding code.

    Decoded as UTF-8 with replacement for non-decodable bytes — the
    point is a human-readable preview, not byte-faithful round-trip.
    """
    span = end - start
    if span >= _CONTEXT_BYTES:
        return data[start:start + _CONTEXT_BYTES].decode("utf-8", errors="replace")

    pad_total = _CONTEXT_BYTES - span
    pad_before = pad_total // 2
    win_start = max(0, start - pad_before)
    # Pull the remaining budget from after the match. If we hit the
    # left boundary, all the slack goes to the right side.
    consumed_before = start - win_start
    win_end = min(len(data), end + (pad_total - consumed_before))
    return data[win_start:win_end].decode("utf-8", errors="replace")


def _redact(matched: bytes, *, as_marker: bool = False) -> str:
    """Shorten ``matched`` to a recognisable redacted form.

    For credential-bearing matches (``as_marker=False``, the default):
    keep the leading + trailing 4 chars so a reviewer can spot which
    key they are looking at without copying the full credential into
    a chat log. The middle is replaced with an ellipsis carrying the
    elided character count.

    For purely structural markers (``as_marker=True`` — PEM block
    headers, Firebase URLs): the matched bytes are public-knowledge
    indicators rather than secrets, so keep the full match verbatim
    so the reviewer can see which variant fired.

    For very short matches (≤8 chars — e.g. a generic 8-char token
    surviving an entropy edge case): keep first 2 + last 2 chars.
    """
    s = matched.decode("utf-8", errors="replace")
    if as_marker:
        return s
    n = len(s)
    if n <= 8:
        return f"{s[:2]}...{s[-2:]}"
    head = 4
    tail = 4
    return f"{s[:head]}...({n - head - tail} chars)...{s[-tail:]}"


def _shannon_entropy(data: bytes) -> float:
    """Bits-per-byte Shannon entropy of ``data``.

    Returns 0.0 for an empty buffer. Used as the cheap filter for
    pattern entries flagged ``needs_entropy_check=True`` — drops
    English-text and repeating-char placeholders that accidentally
    fit a high-length URL-safe shape.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


# ---------------------------------------------------------------------
# Helpers — classify_behavior
# ---------------------------------------------------------------------

def _resolve_behavior_workdir(workdir: str | None) -> Path:
    """Resolve the behavior-report workdir.

    Precedence: explicit ``workdir`` arg → ``ANDROID_MCP_WORKDIR``
    env var (already baked into :data:`_DEFAULT_BEHAVIOR_WORKDIR` at
    import time) → ``~/.android-mcp/work``.
    """
    if workdir:
        return Path(workdir).expanduser().resolve()
    return _DEFAULT_BEHAVIOR_WORKDIR


def _sha256_file(path: Path) -> str:
    """SHA-256 the file at ``path`` in 1 MiB chunks. Hex digest."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _dotted_to_smali(dotted: str) -> str:
    """Translate a dotted Java class name to androguard's smali signature.

    ``java.net.URL`` -> ``Ljava/net/URL;``.
    ``android.provider.Settings$Secure`` -> ``Landroid/provider/Settings$Secure;``.
    Inner-class ``$`` is left as-is (smali keeps the ``$``).
    """
    return f"L{dotted.replace('.', '/')};"


def _smali_to_dotted(smali: str) -> str:
    """Translate a smali class signature back to dotted form.

    ``Ljava/net/URL;`` -> ``java.net.URL``. Anything that does not
    match the ``L...;`` shape is returned verbatim — useful for
    array types (``[B``) and primitive descriptors.
    """
    if smali.startswith("L") and smali.endswith(";"):
        return smali[1:-1].replace("/", ".")
    return smali


def _collect_calls_for_category(
    dx: Any,
    apis: tuple[tuple[str, str], ...],
) -> list[dict[str, Any]]:
    """Walk one category's API list, return per-API caller summaries.

    For each ``(class_dotted, method)`` pair, asks androguard's
    ``Analysis`` instance to enumerate every matching method node
    (typically one external + zero-or-more internal overrides) and
    collects each unique internal caller. External-method callers
    are dropped — only application code that actually invokes the
    API is interesting for behavior classification.

    APIs with zero callers are omitted from the returned list so
    the response stays focused on what the APK actually uses.
    """
    out: list[dict[str, Any]] = []
    for class_dotted, method in apis:
        smali_class = _dotted_to_smali(class_dotted)
        # ``find_methods`` regexes match the smali signature. Anchor
        # the class so ``Lcom/example/Foo;`` does not also catch
        # ``Lcom/example/FooBar;``; ``re.escape`` handles ``$``
        # inner-class separators and ``;`` terminators that would
        # otherwise be meta-characters.
        class_re = f"^{re.escape(smali_class)}$"
        method_re = f"^{re.escape(method)}$"
        callers: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        try:
            target_methods = list(dx.find_methods(classname=class_re, methodname=method_re))
        except (AttributeError, TypeError, ValueError) as exc:
            _log.debug(
                "find_methods failed for %s.%s: %s", class_dotted, method, exc
            )
            continue
        for tm in target_methods:
            try:
                xref_from = tm.get_xref_from()
            except (AttributeError, TypeError) as exc:
                _log.debug("get_xref_from failed on %s.%s: %s", class_dotted, method, exc)
                continue
            for entry in xref_from:
                if len(entry) < 3:
                    continue
                _caller_class_analysis, caller_ma, offset = entry[0], entry[1], entry[2]
                if _is_external(caller_ma):
                    # callers that are themselves external are noise — we
                    # only care about app code reaching the API
                    continue
                caller_smali = _safe_attr(caller_ma, "class_name", default="")
                caller_method_name = _safe_attr(caller_ma, "name", default="")
                try:
                    offset_int = int(offset)
                except (TypeError, ValueError):
                    offset_int = -1
                key = (str(caller_smali), str(caller_method_name), offset_int)
                if key in seen:
                    continue
                seen.add(key)
                callers.append({
                    "caller_class": _smali_to_dotted(str(caller_smali)),
                    "caller_method": str(caller_method_name),
                    "offset": offset_int,
                })
        if callers:
            out.append({
                "class": class_dotted,
                "method": method,
                "callers": callers,
                "caller_count": len(callers),
            })
    return out


def _is_external(method_analysis: Any) -> bool:
    """True when ``method_analysis`` represents an external (non-APK) method.

    Androguard's ``MethodAnalysis.is_external()`` is the canonical
    answer. Falls back to ``False`` when the attribute is absent —
    test doubles often skip it and we want them treated as internal.
    """
    is_ext = getattr(method_analysis, "is_external", None)
    if not callable(is_ext):
        return False
    try:
        return bool(is_ext())
    except (AttributeError, TypeError):
        return False


def _safe_attr(obj: Any, name: str, *, default: Any = None) -> Any:
    """Read ``obj.name`` defensively, returning ``default`` on any failure."""
    try:
        return getattr(obj, name, default)
    except (AttributeError, TypeError):
        return default


def _safe_call(callable_: Any) -> Any:
    """Call ``callable_()`` defensively, returning ``None`` on any failure."""
    if not callable(callable_):
        return None
    try:
        return callable_()
    except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
        _log.debug("safe_call failed: %s", exc)
        return None


# ---------------------------------------------------------------------
# Helpers — verify_capabilities
# ---------------------------------------------------------------------

def _build_capability_profile(apk_path: str) -> MobileCapabilityProfile:
    """Build the :class:`MobileCapabilityProfile` for ``apk_path``.

    Module-level helper shared between the ``verify_capabilities`` tool
    (a thin wrapper) and ``compute_risk_score`` (which reuses the
    profile as one of its risk inputs). Keeping the androguard read
    behind a callable that isn't decorated by FastMCP makes it
    reachable from arbitrary call sites without going through the
    tool registry.

    Raises:
        FileNotFoundError: ``apk_path`` does not exist.
        ValueError: ``apk_path`` exists but is not a file.
    """
    from androguard.core.apk import APK  # local — keeps cold-start fast

    apk_p = Path(apk_path).expanduser().resolve()
    if not apk_p.exists():
        raise FileNotFoundError(f"apk not found: {apk_p}")
    if not apk_p.is_file():
        raise ValueError(f"apk_path is not a file: {apk_p}")

    a = APK(str(apk_p))

    declared_permissions = sorted(_safe_call(a.get_permissions) or [])
    declared_permissions_set = set(declared_permissions)

    intent_actions_by_component = _collect_intent_actions_by_component(a)
    all_declared_actions = sorted({
        action
        for actions in intent_actions_by_component.values()
        for action in actions
    })
    all_declared_actions_set = set(all_declared_actions)

    exported_components = _collect_exported_components(a)
    signing_schemes = _detect_signing_schemes(a)
    deep_link_components = _collect_deep_link_components(a)

    confirmed: list[ConfirmedCapability] = []
    absent: list[AbsentCapability] = []

    for cap_name, cap_info in _MOBILE_CAPABILITIES.items():
        evidence = _evaluate_capability(
            cap_name,
            cap_info,
            declared_permissions_set=declared_permissions_set,
            all_declared_actions_set=all_declared_actions_set,
            exported_components=exported_components,
            deep_link_components=deep_link_components,
            signing_schemes=signing_schemes,
            apk=a,
        )
        if evidence:
            confirmed.append(ConfirmedCapability(
                name=cap_name,
                description=cap_info["description"],
                evidence=evidence,
            ))
        else:
            absent.append(AbsentCapability(
                name=cap_name,
                description=cap_info["description"],
            ))

    uncategorized: list[UncategorizedItem] = []
    for perm in declared_permissions:
        if perm not in _CATALOGUED_PERMISSIONS:
            uncategorized.append(UncategorizedItem(kind="permission", name=perm))
    for action in all_declared_actions:
        if action not in _CATALOGUED_INTENT_ACTIONS:
            uncategorized.append(UncategorizedItem(kind="intent_action", name=action))

    return MobileCapabilityProfile(
        package=_safe_call(a.get_package),
        apk_path=str(apk_p),
        confirmed=confirmed,
        absent=absent,
        uncategorized=uncategorized,
    )


def _collect_intent_actions_by_component(apk: Any) -> dict[tuple[str, str], list[str]]:
    """Walk every (kind, component_name) and pull its intent-filter actions.

    Returns ``{(kind, name): [action_fqn, ...]}``. ``kind`` is one of
    ``activity`` / ``service`` / ``receiver`` / ``provider``. The list
    is deduplicated per component but order is preserved as androguard
    yielded it so the caller can fingerprint a manifest exactly.
    """
    out: dict[tuple[str, str], list[str]] = {}
    for kind in _COMPONENT_KINDS:
        names = _safe_call(_bound_component_getter(apk, kind)) or []
        for name in names:
            filters = _safe_intent_filters(apk, kind, name)
            actions = _extract_actions_from_filters(filters)
            if actions:
                out[(kind, name)] = actions
    return out


# Androguard's component getters do not pluralize uniformly — they
# are ``get_activities`` (with ``-ies``), ``get_services``,
# ``get_receivers``, ``get_providers``. Map kind → method name.
_COMPONENT_GETTERS: dict[str, str] = {
    "activity": "get_activities",
    "service": "get_services",
    "receiver": "get_receivers",
    "provider": "get_providers",
}


def _bound_component_getter(apk: Any, kind: str) -> Any:
    """Return the ``a.get_activities`` / ``get_services`` / ... bound method.

    Returns ``None`` when the attribute is absent so :func:`_safe_call`
    treats it as an empty list.
    """
    method_name = _COMPONENT_GETTERS.get(kind)
    if method_name is None:
        return None
    return getattr(apk, method_name, None)


def _safe_intent_filters(apk: Any, kind: str, name: str) -> Any:
    """Call ``apk.get_intent_filters(kind, name)`` defensively.

    Androguard occasionally raises on malformed components (binary
    XML decode failure on obfuscated manifests); returning ``{}``
    keeps the catalogue scan going for the rest of the components.
    """
    try:
        return apk.get_intent_filters(kind, name)
    except (AttributeError, TypeError, ValueError, KeyError) as exc:
        _log.debug("get_intent_filters failed for %s/%s: %s", kind, name, exc)
        return {}


def _extract_actions_from_filters(filters: Any) -> list[str]:
    """Pull a flat, ordered, deduped action list out of androguard's filters payload.

    Androguard returns either a single ``{"action": [...], "category":
    [...], "data": [...]}`` dict OR a list of those dicts depending on
    component shape and version. Both are handled here so the caller
    never has to special-case.
    """
    if not filters:
        return []
    if isinstance(filters, dict):
        return _dedupe_preserve_order(filters.get("action") or [])
    if isinstance(filters, list):
        out: list[str] = []
        for entry in filters:
            if isinstance(entry, dict):
                out.extend(entry.get("action") or [])
        return _dedupe_preserve_order(out)
    return []


def _collect_categories_from_filters(filters: Any) -> list[str]:
    """Pull the dedup'd category list out of an intent-filters payload."""
    if not filters:
        return []
    if isinstance(filters, dict):
        return _dedupe_preserve_order(filters.get("category") or [])
    if isinstance(filters, list):
        out: list[str] = []
        for entry in filters:
            if isinstance(entry, dict):
                out.extend(entry.get("category") or [])
        return _dedupe_preserve_order(out)
    return []


def _dedupe_preserve_order(items: Any) -> list[str]:
    """Deduplicate ``items`` keeping first-seen order. Non-string entries dropped."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items or []:
        if not isinstance(item, str) or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _collect_exported_components(apk: Any) -> list[dict[str, str]]:
    """Return components reachable from other apps.

    Mirrors ``tools/androguard.py``'s exported-component scan: a
    component counts as exported when android:exported is literally
    ``"true"`` OR when the component has at least one intent-filter
    (Android treats unfiltered components as effectively exported on
    older SDKs). Each entry is ``{kind, name}`` for evidence shape.
    """
    out: list[dict[str, str]] = []
    for kind in _COMPONENT_KINDS:
        names = _safe_call(_bound_component_getter(apk, kind)) or []
        for name in names:
            if _is_component_exported(apk, kind, name):
                out.append({"kind": kind, "name": name})
    return out


def _is_component_exported(apk: Any, kind: str, name: str) -> bool:
    """True when the component has android:exported=true OR any intent-filter."""
    exported_attr = _safe_attribute_value(apk, kind, "exported", name=name)
    if exported_attr.strip().lower() == "true":
        return True
    filters = _safe_intent_filters(apk, kind, name)
    return bool(_extract_actions_from_filters(filters))


def _safe_attribute_value(apk: Any, tag: str, attr: str, **kwargs: Any) -> str:
    """Call ``apk.get_attribute_value(tag, attr, **kwargs)`` defensively.

    Returns the empty string on any failure so callers can compare
    against ``"true"`` / ``"false"`` / specific resource ids without
    branching on exception types.
    """
    getter = getattr(apk, "get_attribute_value", None)
    if not callable(getter):
        return ""
    try:
        result = getter(tag, attr, **kwargs)
    except (AttributeError, TypeError, ValueError, KeyError) as exc:
        _log.debug("get_attribute_value failed for %s/%s: %s", tag, attr, exc)
        return ""
    return result if isinstance(result, str) else ""


def _detect_signing_schemes(apk: Any) -> list[str]:
    """Detect which APK signing schemes are present.

    Returns a list in canonical order (``v1, v2, v3, v3.1``) of the
    schemes that actually have certificate blocks on the APK.
    Androguard exposes ``get_certificates_v{1,2,3,31}`` — any non-
    empty return means the scheme is present.
    """
    schemes: list[str] = []
    for getter_name, label in (
        ("get_certificates_v1", "v1"),
        ("get_certificates_v2", "v2"),
        ("get_certificates_v3", "v3"),
        ("get_certificates_v31", "v3.1"),
    ):
        certs = _safe_call(getattr(apk, getter_name, None))
        if certs:
            schemes.append(label)
    return schemes


def _collect_deep_link_components(apk: Any) -> list[dict[str, str]]:
    """Components with a VIEW + BROWSABLE intent-filter on the same filter.

    Both must appear on the same intent-filter for the Android runtime
    to dispatch a deep link from an external context. Returns
    ``[{kind, name}]`` for use as evidence detail.
    """
    out: list[dict[str, str]] = []
    for kind in _COMPONENT_KINDS:
        names = _safe_call(_bound_component_getter(apk, kind)) or []
        for name in names:
            filters = _safe_intent_filters(apk, kind, name)
            if _filters_have_view_browsable_pair(filters):
                out.append({"kind": kind, "name": name})
    return out


def _filters_have_view_browsable_pair(filters: Any) -> bool:
    """True when at least one intent-filter has BOTH VIEW + BROWSABLE."""
    if not filters:
        return False
    # When androguard returns a single filter dict, treat actions and
    # categories as belonging to the same filter — that's the common
    # case (one intent-filter per component slot).
    if isinstance(filters, dict):
        actions = filters.get("action") or []
        categories = filters.get("category") or []
        return _DEEP_LINK_ACTION in actions and _DEEP_LINK_CATEGORY in categories
    if isinstance(filters, list):
        for entry in filters:
            if not isinstance(entry, dict):
                continue
            actions = entry.get("action") or []
            categories = entry.get("category") or []
            if _DEEP_LINK_ACTION in actions and _DEEP_LINK_CATEGORY in categories:
                return True
    return False


def _evaluate_capability(
    cap_name: str,
    cap_info: dict[str, Any],
    *,
    declared_permissions_set: set[str],
    all_declared_actions_set: set[str],
    exported_components: list[dict[str, str]],
    deep_link_components: list[dict[str, str]],
    signing_schemes: list[str],
    apk: Any,
) -> list[CapabilityEvidence]:
    """Compute the evidence list for one catalogue entry.

    Walks the catalogue entry's permissions / intent_actions /
    manifest_flags against the collected APK signals, then layers
    the four special-cased capabilities on top:

        exported_components            — any entry in
                                         ``exported_components``
        deep_linking                   — any entry in
                                         ``deep_link_components``
        modern_signing_scheme          — any scheme in
                                         ``_MODERN_SIGNING_SCHEMES``
        legacy_signing_scheme_only     — schemes == {"v1"}

    Evidence order is deterministic: catalogue-driven matches first
    (permission, then intent_action, then manifest_flag) and
    special-case evidence last. This gives the reviewer the same
    reading order for every capability.
    """
    evidence: list[CapabilityEvidence] = []

    for perm in cap_info["permissions"]:
        if perm in declared_permissions_set:
            evidence.append(CapabilityEvidence(source="permission", detail=perm))

    for action in cap_info["intent_actions"]:
        if action in all_declared_actions_set:
            evidence.append(CapabilityEvidence(source="intent_action", detail=action))

    for tag, attr, expected in cap_info["manifest_flags"]:
        actual = _safe_attribute_value(apk, tag, attr)
        if not actual:
            continue
        if expected is None or actual.strip().lower() == expected.strip().lower():
            detail = f"{tag}.{attr}={actual}"
            evidence.append(CapabilityEvidence(source="manifest_flag", detail=detail))

    if cap_name == "exported_components":
        for comp in exported_components:
            detail = f"{comp['kind']}:{comp['name']}"
            evidence.append(CapabilityEvidence(source="exported_component", detail=detail))

    if cap_name == "deep_linking":
        for comp in deep_link_components:
            detail = f"VIEW+BROWSABLE@{comp['kind']}:{comp['name']}"
            evidence.append(CapabilityEvidence(source="intent_filter", detail=detail))

    if cap_name == "modern_signing_scheme":
        for scheme in signing_schemes:
            if scheme in _MODERN_SIGNING_SCHEMES:
                evidence.append(CapabilityEvidence(source="signing_scheme", detail=scheme))

    if cap_name == "legacy_signing_scheme_only":
        if signing_schemes == ["v1"]:
            evidence.append(CapabilityEvidence(source="signing_scheme", detail="v1"))

    return evidence


# ---------------------------------------------------------------------
# Helpers — compute_risk_score
# ---------------------------------------------------------------------

def _summarize_native_libs(apk_path: str) -> list[dict[str, Any]]:
    """Walk an APK's ``lib/<abi>/*.so`` entries and summarise each via LIEF.

    Mirrors ``tools.lief_so.analyze_native_libs`` so the risk-score
    handler reaches the same per-library hardening fields without
    going through the FastMCP tool closure. Per-library extraction
    failures surface as ``{"abi", "name", "error"}`` entries — the
    walk does not abort on the first bad library so the score still
    reflects the libraries that DID parse.
    """
    import tempfile
    import zipfile

    from android_mcp.tools.lief_so import (
        _is_native_lib_entry,
        _summarize_elf,
    )

    apk_p = Path(apk_path).expanduser().resolve()
    try:
        zf = zipfile.ZipFile(apk_p)
    except zipfile.BadZipFile:
        return []

    results: list[dict[str, Any]] = []
    with zf:
        so_entries = [
            info for info in zf.infolist() if _is_native_lib_entry(info.filename)
        ]
        if not so_entries:
            return []
        with tempfile.TemporaryDirectory(prefix="android-mcp-risk-") as tmp:
            tmp_dir = Path(tmp)
            for info in so_entries:
                parts = info.filename.split("/")
                abi = parts[1] if len(parts) >= 3 else "unknown"
                so_name = parts[-1]
                out_path = tmp_dir / f"{abi}__{so_name}"
                try:
                    with zf.open(info) as src, out_path.open("wb") as dst:
                        dst.write(src.read())
                except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
                    results.append({
                        "abi": abi,
                        "name": so_name,
                        "error": f"extract failed: {type(exc).__name__}: {exc}",
                    })
                    continue
                results.append(_summarize_elf(abi, so_name, out_path))
    return results


def _factor_exported_components(
    profile: MobileCapabilityProfile,
    drozer_scan: dict[str, Any] | None,
) -> RiskFactor:
    """Risk from exported components reachable by other apps on the device.

    Prefers drozer's per-kind counts (activities + services + receivers
    + providers) because they reflect what the on-device installer
    treats as actually exported. Falls back to the manifest-derived
    exported list on the capability profile when drozer isn't
    available — the count is from manifest evidence collected by
    androguard. Per-component weight applies; the factor caps at
    ``_RISK_CAP_EXPORTED_COMPONENT``.
    """
    evidence: list[str] = []
    count = 0
    if isinstance(drozer_scan, dict):
        comps = drozer_scan.get("exported_components")
        if isinstance(comps, dict):
            for kind in ("activities", "receivers", "providers", "services"):
                kind_count = comps.get(kind, 0)
                if isinstance(kind_count, int) and kind_count > 0:
                    count += kind_count
                    evidence.append(f"drozer:{kind}={kind_count}")
    if count == 0:
        # Fall back to the capability profile's evidence list — each
        # exported component contributes one row of evidence with
        # source=exported_component on the confirmed entry.
        for c in profile.confirmed:
            if c.name == "exported_components":
                for ev in c.evidence:
                    if ev.source == "exported_component":
                        count += 1
                        evidence.append(f"manifest:{ev.detail}")
                break
    contribution = min(
        count * _RISK_W_EXPORTED_COMPONENT, _RISK_CAP_EXPORTED_COMPONENT,
    )
    return RiskFactor(
        factor="exported_components",
        weight=_RISK_W_EXPORTED_COMPONENT,
        contribution=contribution,
        evidence=evidence,
    )


def _factor_v1_only_signing(confirmed_names: set[str]) -> RiskFactor:
    """Risk from APKs signed only with v1 (Janus / CVE-2017-13156).

    The capability profile lands the ``legacy_signing_scheme_only``
    entry in ``confirmed`` exactly when androguard's signing-block
    walk found v1 alone. One signal, one fixed weight.
    """
    janus = "legacy_signing_scheme_only" in confirmed_names
    return RiskFactor(
        factor="v1_only_signing",
        weight=_RISK_W_V1_ONLY_SIGNING,
        contribution=_RISK_W_V1_ONLY_SIGNING if janus else 0,
        evidence=(
            ["legacy_signing_scheme_only confirmed — v1 only (Janus on API <= 25)"]
            if janus
            else []
        ),
    )


def _factor_world_writable(mobsf_report: dict[str, Any] | None) -> RiskFactor:
    """Risk from world-writable / world-readable file creation.

    Scans the MobSF report for any code_analysis rule whose ID
    contains a token from :data:`_MOBSF_WORLD_WRITABLE_TOKENS`. MobSF
    flags ``openFileOutput(..., MODE_WORLD_WRITABLE)`` and adjacent
    patterns under multiple rule-id variants across releases; the
    substring match keeps the factor stable.
    """
    findings = _walk_mobsf_findings(mobsf_report, _MOBSF_WORLD_WRITABLE_TOKENS)
    contribution = min(
        len(findings) * _RISK_W_WORLD_WRITABLE, _RISK_CAP_WORLD_WRITABLE,
    )
    return RiskFactor(
        factor="world_writable_files",
        weight=_RISK_W_WORLD_WRITABLE,
        contribution=contribution,
        evidence=findings,
    )


def _factor_missing_pinning(mobsf_report: dict[str, Any] | None) -> RiskFactor:
    """Risk from a customer-facing app shipping without certificate pinning.

    MobSF surfaces pinning absence as a finding (e.g.
    ``android_certificate_pinning``). The factor fires once when ANY
    pinning-related finding is present (not per finding) — a single
    "no pinning" verdict is the underlying signal.
    """
    findings = _walk_mobsf_findings(mobsf_report, _MOBSF_MISSING_PINNING_TOKENS)
    fires = bool(findings)
    return RiskFactor(
        factor="missing_certificate_pinning",
        weight=_RISK_W_MISSING_PINNING,
        contribution=_RISK_W_MISSING_PINNING if fires else 0,
        evidence=findings if fires else [],
    )


def _factor_missing_pie(native_libs: list[dict[str, Any]]) -> RiskFactor:
    """Risk from native libraries built without position-independent code.

    LIEF's ELF-type check returns ``DYN`` for any shared object, so
    PIE is reported as True for every well-formed ``.so``. A False
    here means the library is a static executable mistakenly packed
    into ``lib/<abi>/`` — extremely rare but worth catching.
    """
    return _per_lib_hardening_factor(
        native_libs,
        factor_name="missing_pie_per_native_lib",
        weight=_RISK_W_MISSING_PIE,
        predicate=lambda h: h.get("pie") is False,
    )


def _factor_missing_nx(native_libs: list[dict[str, Any]]) -> RiskFactor:
    """Risk from native libraries with an executable stack."""
    return _per_lib_hardening_factor(
        native_libs,
        factor_name="missing_nx_per_native_lib",
        weight=_RISK_W_MISSING_NX,
        predicate=lambda h: h.get("nx") is False,
    )


def _factor_weak_relro(native_libs: list[dict[str, Any]]) -> RiskFactor:
    """Risk from native libraries with partial or absent RELRO.

    ``"partial"`` contributes one point per lib; ``"none"`` contributes
    three. ``"full"`` contributes nothing. The factor's ``weight``
    field reports the "none" weight so the consumer sees the worst
    per-unit cost.
    """
    contribution = 0
    evidence: list[str] = []
    for lib in native_libs:
        hardening = lib.get("hardening") if isinstance(lib, dict) else None
        if not isinstance(hardening, dict):
            continue
        relro = hardening.get("relro")
        abi = lib.get("abi", "unknown")
        name = lib.get("name", "unknown")
        if relro == "partial":
            contribution += _RISK_W_WEAK_RELRO_PARTIAL
            evidence.append(f"{abi}/{name} relro=partial")
        elif relro == "none":
            contribution += _RISK_W_WEAK_RELRO_NONE
            evidence.append(f"{abi}/{name} relro=none")
    return RiskFactor(
        factor="weak_relro_per_native_lib",
        weight=_RISK_W_WEAK_RELRO_NONE,
        contribution=contribution,
        evidence=evidence,
    )


def _factor_missing_stack_canary(native_libs: list[dict[str, Any]]) -> RiskFactor:
    """Risk from native libraries built without ``-fstack-protector``."""
    return _per_lib_hardening_factor(
        native_libs,
        factor_name="missing_stack_canary_per_native_lib",
        weight=_RISK_W_MISSING_CANARY,
        predicate=lambda h: h.get("canary") is False,
    )


def _factor_debuggable(
    confirmed_names: set[str],
    profile: MobileCapabilityProfile,
) -> RiskFactor:
    """Risk from ``android:debuggable=true`` shipped in a production build.

    JDWP attaches from any process holding the right permission;
    debuggable production apps are remote-code-execution-by-design.
    Single signal, fixed weight.
    """
    fires = "debuggable_build" in confirmed_names
    return RiskFactor(
        factor="debuggable_build",
        weight=_RISK_W_DEBUGGABLE,
        contribution=_RISK_W_DEBUGGABLE if fires else 0,
        evidence=_capability_evidence_details(profile, "debuggable_build"),
    )


def _factor_cleartext_traffic(
    confirmed_names: set[str],
    profile: MobileCapabilityProfile,
) -> RiskFactor:
    """Risk from ``android:usesCleartextTraffic=true``."""
    fires = "cleartext_traffic_allowed" in confirmed_names
    return RiskFactor(
        factor="cleartext_traffic_allowed",
        weight=_RISK_W_CLEARTEXT,
        contribution=_RISK_W_CLEARTEXT if fires else 0,
        evidence=_capability_evidence_details(profile, "cleartext_traffic_allowed"),
    )


def _factor_backup_allowed(
    confirmed_names: set[str],
    profile: MobileCapabilityProfile,
) -> RiskFactor:
    """Risk from ``android:allowBackup=true`` exposing app data via adb / cloud."""
    fires = "backup_allowed" in confirmed_names
    return RiskFactor(
        factor="backup_allowed",
        weight=_RISK_W_BACKUP_ALLOWED,
        contribution=_RISK_W_BACKUP_ALLOWED if fires else 0,
        evidence=_capability_evidence_details(profile, "backup_allowed"),
    )


def _factor_provider_injection(drozer_scan: dict[str, Any] | None) -> RiskFactor:
    """Risk from content-provider injection findings reported by drozer.

    drozer's ``scanner.provider.injection`` returns a list of URIs +
    vectors (``projection`` / ``selection``). Each finding contributes
    the per-unit weight up to the cap.
    """
    evidence: list[str] = []
    if isinstance(drozer_scan, dict):
        finder = drozer_scan.get("finder_results")
        if isinstance(finder, dict):
            findings = finder.get("provider_injection")
            if isinstance(findings, list):
                for entry in findings:
                    if not isinstance(entry, dict):
                        continue
                    uri = entry.get("uri", "?")
                    vector = entry.get("vector", "?")
                    evidence.append(f"{uri} ({vector})")
    contribution = min(
        len(evidence) * _RISK_W_PROVIDER_INJECTION,
        _RISK_CAP_PROVIDER_INJECTION,
    )
    return RiskFactor(
        factor="provider_injection_finding",
        weight=_RISK_W_PROVIDER_INJECTION,
        contribution=contribution,
        evidence=evidence,
    )


def _per_lib_hardening_factor(
    native_libs: list[dict[str, Any]],
    *,
    factor_name: str,
    weight: int,
    predicate: Any,
) -> RiskFactor:
    """Shared per-library hardening evaluator.

    Walks every entry in ``native_libs``, applies ``predicate`` to
    the ``hardening`` sub-dict, and tallies one weight per True
    return. Libraries without a ``hardening`` block (extraction
    failures, parse failures) are skipped silently — the operator
    sees them under ``analyze_native_libs`` separately.
    """
    evidence: list[str] = []
    for lib in native_libs:
        hardening = lib.get("hardening") if isinstance(lib, dict) else None
        if not isinstance(hardening, dict):
            continue
        if predicate(hardening):
            abi = lib.get("abi", "unknown")
            name = lib.get("name", "unknown")
            evidence.append(f"{abi}/{name}")
    return RiskFactor(
        factor=factor_name,
        weight=weight,
        contribution=len(evidence) * weight,
        evidence=evidence,
    )


def _capability_evidence_details(
    profile: MobileCapabilityProfile, capability_name: str,
) -> list[str]:
    """Return the ``detail`` strings of every evidence row on a confirmed capability.

    Returns an empty list when the capability is absent — the caller
    has already decided whether to fire the factor, so the empty list
    just means "no evidence to surface for this factor's evidence
    column".
    """
    for c in profile.confirmed:
        if c.name == capability_name:
            return [ev.detail for ev in c.evidence]
    return []


def _walk_mobsf_findings(
    mobsf_report: dict[str, Any] | None,
    tokens: tuple[str, ...],
) -> list[str]:
    """Pull rule IDs containing any of ``tokens`` from a MobSF report.

    Two shapes are tolerated:
      * the native MobSF shape — ``code_analysis: {rule_id: {...}}``
      * a flat list — ``findings: [{rule_id: ..., file: ..., ...}, ...]``

    Returns the matching rule IDs (deduped, sorted) plus, where the
    rule's files dict is present, one or two example ``file:line``
    rows for the evidence column. Multiple shapes coexist across
    MobSF versions so the walker accepts both rather than picking a
    rigid contract.
    """
    if not isinstance(mobsf_report, dict):
        return []
    matches: list[str] = []
    seen: set[str] = set()

    code_analysis = mobsf_report.get("code_analysis")
    if isinstance(code_analysis, dict):
        for rule_id, payload in code_analysis.items():
            rule_id_l = str(rule_id).lower()
            if not any(tok in rule_id_l for tok in tokens):
                continue
            if rule_id in seen:
                continue
            seen.add(rule_id)
            entry = rule_id
            if isinstance(payload, dict):
                files = payload.get("files")
                if isinstance(files, dict) and files:
                    sample = next(iter(files.items()))
                    entry = f"{rule_id} ({sample[0]})"
            matches.append(entry)

    findings = mobsf_report.get("findings")
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            rule_id = f.get("rule_id") or f.get("rule") or f.get("type")
            if rule_id is None:
                continue
            rule_id_l = str(rule_id).lower()
            if not any(tok in rule_id_l for tok in tokens):
                continue
            if rule_id in seen:
                continue
            seen.add(rule_id)
            location = f.get("file") or f.get("path")
            line = f.get("line")
            if location and line is not None:
                matches.append(f"{rule_id} ({location}:{line})")
            elif location:
                matches.append(f"{rule_id} ({location})")
            else:
                matches.append(str(rule_id))

    return sorted(matches)
