/*
 * android_basic.yar — bundled default ruleset for yara_scan_dir.
 *
 * Three buckets, keyed by rule tag so a downstream caller can group
 * matches without re-parsing the description:
 *
 *   hardcoded_secrets : AWS / Google / Firebase / JWT / PEM literals
 *   debug_flags       : android.util.Log calls + stack-trace dumps
 *                       left behind in shipped code
 *   unsafe_crypto     : ECB-mode Cipher, MD5 / SHA-1 digests, no-op
 *                       X509TrustManager.checkServerTrusted bodies
 *
 * Used by tools/yara_decompiled.py::yara_scan_dir when no
 * ruleset_path is supplied. Operators that need richer or
 * site-specific rules pass their own .yar file via ruleset_path.
 */

rule android_secret_aws_access_key : secret hardcoded_secrets
{
    meta:
        category = "hardcoded-secrets"
        description = "AWS access key ID literal"

    strings:
        $aws = /AKIA[0-9A-Z]{16}/

    condition:
        $aws
}

rule android_secret_google_api_key : secret hardcoded_secrets
{
    meta:
        category = "hardcoded-secrets"
        description = "Google API key literal"

    strings:
        $g = /AIza[0-9A-Za-z_\-]{35}/

    condition:
        $g
}

rule android_secret_pem_private_key : secret hardcoded_secrets
{
    meta:
        category = "hardcoded-secrets"
        description = "PEM-encoded private key block"

    strings:
        $pem = "-----BEGIN PRIVATE KEY-----" ascii wide
        $pem_rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii wide
        $pem_ec = "-----BEGIN EC PRIVATE KEY-----" ascii wide

    condition:
        any of them
}

rule android_secret_firebase_url : secret hardcoded_secrets
{
    meta:
        category = "hardcoded-secrets"
        description = "Firebase Realtime Database URL"

    strings:
        $fb = /https:\/\/[a-z0-9\-]+\.firebaseio\.com/

    condition:
        $fb
}

rule android_secret_jwt_token : secret hardcoded_secrets
{
    meta:
        category = "hardcoded-secrets"
        description = "JSON Web Token literal (three base64url segments)"

    strings:
        $jwt = /eyJ[A-Za-z0-9_\-]{18,}\.eyJ[A-Za-z0-9_\-]{18,}\.[A-Za-z0-9_\-]{20,}/

    condition:
        $jwt
}

rule android_debug_log_call : debug debug_flags
{
    meta:
        category = "debug-flags"
        description = "android.util.Log debug/verbose call or printStackTrace left in shipped code"

    strings:
        $log_d = "Log.d("
        $log_v = "Log.v("
        $log_i = "Log.i("
        $printstack = ".printStackTrace()"

    condition:
        any of them
}

rule android_unsafe_crypto_ecb : crypto unsafe_crypto
{
    meta:
        category = "unsafe-crypto"
        description = "AES / DES / 3DES used in ECB mode (deterministic, no semantic security)"

    strings:
        $ecb_aes = "AES/ECB/"
        $ecb_des = "DES/ECB/"
        $ecb_3des = "DESede/ECB/"

    condition:
        any of them
}

rule android_unsafe_crypto_legacy_digest : crypto unsafe_crypto
{
    meta:
        category = "unsafe-crypto"
        description = "Legacy MD5 / SHA-1 message-digest usage"

    strings:
        $md5 = "MessageDigest.getInstance(\"MD5\""
        $sha1_dash = "MessageDigest.getInstance(\"SHA-1\""
        $sha1 = "MessageDigest.getInstance(\"SHA1\""

    condition:
        any of them
}

rule android_unsafe_trust_manager : crypto unsafe_crypto
{
    meta:
        category = "unsafe-crypto"
        description = "Custom X509TrustManager with empty checkServerTrusted body (cert validation bypass)"

    strings:
        $tm = "X509TrustManager"
        $check = "checkServerTrusted"
        $empty = /void\s+checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/

    condition:
        $tm and $check and $empty
}
