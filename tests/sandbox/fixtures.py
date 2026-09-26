"""Sandbox test fixtures: synthetic keys, obfuscated payloads, and mock responses."""

from __future__ import annotations

import base64

# =====================================================================
# Synthetic Keys (Format-valid, non-real keys for safe testing)
# =====================================================================

TEST_KEYS = {
    "google_valid": "AIzaSyDummyGoogleKeyForSandboxValid1234",
    "google_bypass": "AIzaSyDummyGoogleKeyReferrerProtected12",
    "google_rate_limited": "AIzaSyDummyGoogleKeyRateLimited12345678",
    "google_invalid": "AIzaSyDummyGoogleKeyInvalidKey000000000",
    
    "openai_standard": "sk-" + "a" * 48,
    "openai_project": "sk-proj-DummyOpenAIProjectKeyForTestingSandbox1234567890abcdef",
    "openai_org": "org-DummyOpenAIOrgKey1234567",
    "openai_invalid": "sk-" + "0" * 48,

    "anthropic_valid": "sk-ant-api03-" + "B" * 95,
    "anthropic_invalid": "sk-ant-api03-" + "0" * 95,

    "nvidia_valid": "nvapi-" + "C" * 56,
    "nvidia_invalid": "nvapi-" + "0" * 56,
}

# =====================================================================
# Helper to create obfuscated variations of keys
# =====================================================================

def make_hex_encoded(key: str) -> str:
    """Encode AIzaSy prefix as hex escapes: \\x41\\x49\\x7a\\x61\\x53\\x79."""
    if key.startswith("AIzaSy"):
        return r"\x41\x49\x7a\x61\x53\x79" + key[6:]
    return key


def make_reversed_key(key: str) -> str:
    """Reverse the key string."""
    return key[::-1]


def make_base64_encoded(key: str) -> str:
    """Base64 encode the key."""
    return base64.b64encode(key.encode("utf-8")).decode("utf-8")


# =====================================================================
# Mock Web Assets (HTML, JS, Source Maps, Webpack Chunks)
# =====================================================================

MOCK_INDEX_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sandbox Test Application</title>
    <script>
        // Inline Google Key
        window.GEMINI_KEY = "{TEST_KEYS['google_valid']}";
    </script>
    <script src="/static/app.js"></script>
    <script src="/static/vendor.js"></script>
    <script src="/static/chunks/manifest.js"></script>
</head>
<body>
    <h1>LLMHunter Test Sandbox</h1>
    <p>Target vulnerable application serving multi-provider keys across various formats.</p>
</body>
</html>
"""

MOCK_APP_JS = f"""
// Client application logic
(function() {{
    console.log("App initializing...");

    // 1. Direct OpenAI project key
    const OPENAI_API_KEY = "{TEST_KEYS['openai_project']}";

    // 2. Concatenated Google Bypass Key
    const GOOGLE_BYPASS_KEY = "AIzaSy" + "{TEST_KEYS['google_bypass'][6:]}";

    // 3. Array Join Google Key
    const GOOGLE_JOIN_KEY = ["AIzaSy", "{TEST_KEYS['google_rate_limited'][6:]}"].join("");

    // 4. Hex-encoded prefix key
    const HEX_KEY = "{make_hex_encoded(TEST_KEYS['google_valid'])}";

    // 5. Base64 encoded key in config
    const B64_KEY = "{make_base64_encoded(TEST_KEYS['google_valid'])}";

    // 6. Reversed key string
    const REV_KEY = "{make_reversed_key(TEST_KEYS['google_valid'])}";

    // 7. OpenAI Standard Key in fallback pattern
    const key = process.env.API_KEY || "{TEST_KEYS['openai_standard']}";
}})();
"""

MOCK_VENDOR_JS = """
// Third-party vendor bundle
(function() {
    console.log("Vendor bundle loaded");
})();
//# sourceMappingURL=/static/vendor.js.map
"""

MOCK_VENDOR_SOURCE_MAP = f"""{{
  "version": 3,
  "file": "vendor.js",
  "sources": ["src/anthropic_client.ts", "src/nvidia_client.ts"],
  "sourcesContent": [
    "// Anthropic unminified integration\\nexport const anthropicKey = '{TEST_KEYS['anthropic_valid']}';\\n",
    "// NVIDIA NIM unminified integration\\nexport const nvidiaKey = '{TEST_KEYS['nvidia_valid']}';\\n"
  ],
  "names": [],
  "mappings": "AAAA;ACAA"
}}"""

MOCK_MANIFEST_JS = """
// Webpack dynamic chunk manifest
window.webpackChunkManifest = {
    0: "/static/chunks/chunk.0.js",
    1: "/static/chunks/chunk.1.js"
};
"""

MOCK_CHUNK_0_JS = f"""
// Webpack Chunk 0
(window.webpackJsonp = window.webpackJsonp || []).push([[0], {{
    101: function(module, exports) {{
        module.exports = {{
            orgId: "{TEST_KEYS['openai_org']}",
            serviceKey: "{TEST_KEYS['google_bypass']}"
        }};
    }}
}}]);
"""

MOCK_CHUNK_1_JS = f"""
// Webpack Chunk 1
(window.webpackJsonp = window.webpackJsonp || []).push([[1], {{
    202: function(module, exports) {{
        module.exports = {{
            nvidiaKey: "{TEST_KEYS['nvidia_valid']}"
        }};
    }}
}}]);
"""
