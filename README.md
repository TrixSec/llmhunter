# llmhunter

<p align="center">
  Find, extract, validate, bypass restrictions, and gather intelligence on exposed LLM API keys across major AI providers.
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"></a>
</p>

---

## 📌 Overview

**`llmhunter`** is an asynchronous Python CLI tool and framework engineered to discover exposed Large Language Model (LLM) API keys across web targets and client assets. It extracts candidate keys, deobfuscates hidden payloads, validates them against provider endpoints, probes for HTTP header restrictions (such as referrer restrictions), and gathers capability intelligence.

### 🌐 Supported Providers

| Provider | Supported Formats | Validation Endpoint | Intelligence & Capability |
|---|---|---|---|
| **Google Gemini** | `AIzaSy...` (39 chars) | `/v1beta/models` | Models list, tuned models, project ID, billing, referrer bypass |
| **OpenAI** | `sk-...`, `sk-proj-...`, `org-...` | `/v1/models` | Available model list, organization detection |
| **Anthropic Claude** | `sk-ant-api03-...`, `sk-ant-...` | `/v1/messages` | Message validation & model access |
| **NVIDIA NIM** | `nvapi-...` (62 chars) | `/v1/models` | NVIDIA NIM endpoint models list |

---

## 🚀 Key Features

* **Multi-Source Web Discovery**:
  * Crawls inline `<script>` tags, external JS assets, JSON manifests, and framework bundles.
  * Uncovers unminified source code via JavaScript Source Maps (`.js.map`).
  * Parses dynamic Webpack chunk manifests and chunk bundles.
  * Queries historical snapshots via the Wayback Machine (CDX API).
* **Deobfuscation Engine**:
  * Parallelized string normalization (`ThreadPoolExecutor`).
  * Reconstructs split string concatenations (`"AIzaSy" + "..."`).
  * Extracts array `.join()`, template literals (`` `sk-${var}` ``), hex escape sequences (`\x41\x49...`), Base64 strings, and reversed key payloads.
* **403 Restriction Bypass Probing**:
  * Automatically detects referrer/origin-restricted keys.
  * Injects candidate HTTP headers (`Referer`, `Origin`, `X-Goog-Api-Key`) derived from source domain contexts to test for authorization bypasses.
* **Reporting & Evidence Generation**:
  * Rich terminal tables with key status highlighting.
  * Machine-readable JSON output schemas.
  * Shell-quoted `curl` commands to reproduce key validation and bypass findings.
* **Offline Testing Sandbox**:
  * Integrated mock web target & mock provider servers for 100% offline testing.

---

## 🛠️ Installation

Requires **Python 3.11+**.

```bash
# Clone the repository
git clone https://github.com/TrixSec/llmhunter.git
cd llmhunter

# Install directly
pip install .
```

For development mode:
```bash
pip install -e .
```

Verify installation:
```bash
llmhunter --help
```

---

## 💡 Quick Start & Usage

### 1. Web Target Discovery
Discover and assess exposed LLM keys on a domain or full URL:
```bash
llmhunter example.com
```

### 2. Multi-Target Scanning
Scan multiple targets from a text file or pipe:
```bash
llmhunter -f targets.txt --concurrency 20
cat targets.txt | llmhunter --json
```

### 3. Direct Key Validation Mode
Validate previously collected keys directly without web crawling:
```bash
llmhunter --key-file keys.txt
# Or via CLI argument / pipe
llmhunter -k sk-proj-1234567890abcdef...
cat keys.txt | llmhunter -k -
```

### 4. Filter by Provider
Target specific AI providers using `--provider`:
```bash
llmhunter example.com --provider anthropic --provider openai
```

### 5. Save Output & Evidence
Generate JSON reports and shell-escaped `curl` proof of concept commands:
```bash
llmhunter example.com -o report.json --evidence
```

---

## 🧪 Testing Sandbox

`llmhunter` includes a zero-dependency offline testing sandbox that spins up a mock target web server (serving obfuscated HTML/JS/Source Maps/Chunks) and a mock LLM provider server:

```powershell
# Run the interactive CLI sandbox runner
$env:PYTHONPATH="src;."
python -m tests.sandbox.runner
```

```powershell
# Run automated pytest suite
$env:PYTHONPATH="src;."
pytest -v
```

---

## 📐 Project Architecture

```
llmhunter/
├── src/llmhunter/
│   ├── providers/          # Modular provider adapters (google, openai, anthropic, nvidia)
│   ├── discovery/          # Web crawler, sourcemap chaser, webpack finder, wayback fetcher
│   ├── extraction/         # Pattern matching, deobfuscator, key extractor
│   ├── validation/         # Key validation & restriction bypass engine
│   ├── intelligence/       # Model, quota, & project reconnaissance
│   ├── network/            # Async session management, proxy rotation, token bucket rate limiter
│   └── output/             # Terminal table rendering, JSON export, curl evidence
└── tests/
    └── sandbox/            # Mock target server, mock LLM API server, test fixtures & runner
```

---

## ⚠️ Security & Usage Disclaimer

This tool is designed strictly for authorized security assessments, penetration testing, and defense research. 

`llmhunter` performs active HTTP requests to provider API endpoints to validate key status, which consumes quota and leaves logs on target services. Do not use this tool on targets without explicit authorization.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
