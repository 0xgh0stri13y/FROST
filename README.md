<div align="center">

<img src="Frost%20CRLF%20Injection%20Scanner%20Banner.png" alt="FROST — CRLF Injection Scanner" width="100%">

<br>

[![Python](https://img.shields.io/badge/Python-3.10+-7dd8f8?style=for-the-badge&logo=python&logoColor=0d1117)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-7dd8f8?style=for-the-badge&logoColor=0d1117)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-7dd8f8?style=for-the-badge&logoColor=0d1117)](https://github.com/0xgh0stri13y/FROST)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-7dd8f8?style=for-the-badge&logoColor=0d1117)](https://github.com/0xgh0stri13y/FROST/pulls)

<br>

<samp>

`🎯 Probe` &nbsp;·&nbsp; `💉 Inject` &nbsp;·&nbsp; `❄️ Expose`

</samp>

<br>

> *High-accuracy CRLF injection scanner with multi-signal detection,*
> *raw TCP verification, and near-zero false positives.*

</div>

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/lightning-bolt.png" width="22"/> &nbsp; Features

<table>
<tr>
<td width="50%">

### ❄️ 50+ Payloads
Standard, double-encoded, Unicode overlong, null-byte prefixed, mixed-case, and response-splitting variants across **path and query** injection points

### ⚡ True Async Concurrency
`asyncio` + `aiohttp` for blazing-fast parallel testing with configurable concurrency and optional **per-request delay + jitter**

### 🧠 Multi-Signal Detection Engine
Five independent, weighted signals — injected cookie, injected header, header count delta, new header names, body reflection — combined into a single confidence score

### 🔌 Raw TCP Verification
HIGH/CONFIRMED findings are re-confirmed via a **raw socket** to bypass HTTP library header normalization — ground-truth at the protocol level

</td>
<td width="50%">

### 🛡️ False-Positive Guard
A **control request** (marker without any CRLF) detects generic server echo behavior and suppresses body-reflection as evidence when it fires unconditionally

### 📊 Confidence Scoring
Weighted signals map to `LOW` / `MEDIUM` / `HIGH` / `CONFIRMED` with a percentage readout and color-coded terminal output

### 📲 Telegram Alerts
Real-time per-finding notifications and a scan-completion summary report sent to your Telegram chat; credentials can be passed as **env vars** to stay out of shell history

### 🌐 Proxy & Header Control
HTTP and SOCKS5 proxy support, custom request headers, follow-redirects toggle, and pipeline-safe `--json` mode

</td>
</tr>
</table>

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/package.png" width="22"/> &nbsp; Installation

```bash
git clone https://github.com/0xgh0stri13y/FROST.git
cd FROST
pip install -r requirements.txt
```

> [!NOTE]
> Requires **Python 3.10+**. `aiohttp-socks` is optional — only needed for SOCKS5 proxy support.

| Package | Purpose | Required |
|:--------|:--------|:--------:|
| `aiohttp` | Async HTTP client | ✅ |
| `colorama` | Windows terminal color support | ✅ |
| `aiohttp-socks` | SOCKS5 proxy connector | Optional |

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/rocket.png" width="22"/> &nbsp; Usage

```bash
python crlf_scanner.py -u <target_url> [options]
```

### ⚙️ Options

| Flag | Description | Default |
|:-----|:------------|:-------:|
| `-u`, `--url` | **Required** (or `-l`). Single target URL | — |
| `-l`, `--list` | File of URLs to scan, one per line | — |
| `-t`, `--threads` | Concurrent request limit | `10` |
| `-p`, `--proxy` | Proxy URL (`http://…` or `socks5://…`) | — |
| `-o`, `--output` | Save results to file (`.json` or `.txt`) | — |
| `--timeout` | Per-request timeout in seconds | `10` |
| `--delay` | Base delay + jitter between requests | `0` |
| `--follow-redirects` | Follow HTTP redirects | `off` |
| `--headers` | Custom headers in `Key:Value` format | — |
| `--no-raw-verify` | Skip raw TCP verification (faster, less accurate) | `off` |
| `--telegram-token` | Telegram Bot API token | — |
| `-c`, `--chatid` | Telegram Chat ID for alerts | — |
| `-v`, `--verbose` | Print every payload request | `off` |
| `--json` | Write clean JSON to stdout (progress → stderr) | `off` |

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/idea.png" width="22"/> &nbsp; Examples

<details>
<summary><b>🟢 Basic Scan</b></summary>
<br>

```bash
python crlf_scanner.py -u https://example.com
```

</details>

<details>
<summary><b>🟡 Scan a URL List + Save JSON Report</b></summary>
<br>

```bash
python crlf_scanner.py -l urls.txt -o results.json
```

</details>

<details>
<summary><b>🔴 High-Concurrency Scan with Verbose Output</b></summary>
<br>

```bash
python crlf_scanner.py -l urls.txt -t 50 -v
```

</details>

<details>
<summary><b>🟠 Route Through Burp Suite</b></summary>
<br>

```bash
python crlf_scanner.py -u https://example.com -p http://127.0.0.1:8080
```

</details>

<details>
<summary><b>❄️ Polite Scan with Rate Limiting</b></summary>
<br>

```bash
python crlf_scanner.py -u https://example.com --delay 0.5 -t 5
```

Each request waits a base of 0.5 s plus up to 0.5 s of random jitter before firing.

</details>

<details>
<summary><b>🤖 Real-Time Telegram Alerts</b></summary>
<br>

```bash
python crlf_scanner.py -l urls.txt \
  --telegram-token "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ" \
  -c "987654321"
```

</details>

<details>
<summary><b>🔧 Pipeline-Friendly JSON Output</b></summary>
<br>

```bash
# All progress goes to stderr; stdout is pure JSON
python crlf_scanner.py -u https://example.com --json | jq '.[].confidence'
```

</details>

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/report-card.png" width="22"/> &nbsp; Output

> [!IMPORTANT]
> Every finding includes a **PoC URL**, full evidence dictionary, and confidence score so you know exactly what was detected and why.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🎯 Target: http://127.0.0.1:8000/vuln/test
  📦 Payloads: 54
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [✓] Baseline: HTTP 200 | 4 headers | 22 bytes
  [✓] Control : clean (no generic echo of the marker)
  [⏳] Testing 54 payloads...

  💥 VULNERABLE!
  ├─ Confidence : CONFIRMED (100%)
  ├─ Payload    : Set-Cookie injection via %0d%0a
  ├─ PoC URL    : http://127.0.0.1:8000/vuln/test/%0d%0aSet-Cookie:gh0stri13y=0xgh0stri13y
  └─ Evidence   : {"injected_cookie": "gh0stri13y=0xgh0stri13y", "raw_injected_cookie": true}

══════════════════════════════════════════════════════════════════════
  📊 SCAN SUMMARY
══════════════════════════════════════════════════════════════════════
  URLs scanned       : 1
  Total requests     : 55
  Payloads tested    : 54
  Elapsed time       : 2.3s
  Requests/second    : 23.5
  Errors             : 0

  Vulnerabilities    : 2
    ├─ Confirmed     : 2
    ├─ High          : 0
    └─ Medium        : 0
══════════════════════════════════════════════════════════════════════
```

**Confidence levels**

| Level | Score | Meaning |
|:-----:|:-----:|:--------|
| 🔴 **CONFIRMED** | ≥ 80% | Injected header found in parsed response **and** raw TCP verified |
| 🟠 **HIGH** | ≥ 50% | Injected header found in parsed response |
| 🟡 **MEDIUM** | ≥ 25% | Suspicious signals (extra headers, header count delta) |
| ⚪ **LOW** | < 25% | Weak signals only |

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/settings.png" width="22"/> &nbsp; How It Works

### 1 · Baseline & Control Requests
Two clean requests fire before any payload:
- **Baseline** — captures the normal response (status, header count, body) for delta comparison.
- **Control** — sends the marker string with *no* CRLF sequence. If the marker appears in the body anyway, body-reflection is globally suppressed for this target — it's generic server echo, not injection.

### 2 · Concurrent Payload Injection

| Category | Example | Point |
|:---------|:--------|:-----:|
| Standard | `%0d%0a` | Path + Query |
| Double-encoded | `%250d%250a` | Path |
| Unicode overlong | `%e5%98%8a%e5%98%8d` | Path |
| Null-byte prefixed | `%00%0d%0a` | Path |
| Mixed case | `%0d%0A` | Path |
| Response splitting | `%0d%0a%0d%0a<html>…` | Path |

### 3 · Multi-Signal Scoring

| Signal | Weight | Description |
|:-------|:------:|:------------|
| Injected `Set-Cookie` | 0.50 | Marker cookie found as a standalone pair in response headers |
| Injected custom header | 0.50 | `X-gh0stri13y` found in response headers |
| Header count anomaly | 0.15 | Response has more headers than baseline |
| New header names | 0.20 | Headers present that weren't in the baseline |
| Body reflection | 0.40 | Marker in body — only counted when control is clean |

### 4 · Raw Socket Verification
For `HIGH` / `CONFIRMED` findings the payload is re-sent over a **raw TCP socket**. Regexes are anchored to real line boundaries (`\r\n`) so marker text merely reflected inside a sanitized single-line value is never mistaken for a true header split.

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/robot.png" width="22"/> &nbsp; Telegram Notifications

1. **Create a bot** — search `@BotFather` in Telegram, type `/newbot`, copy the **API Token**.
2. **Get your Chat ID** — message `@userinfobot` or `@raw_data_bot`.
3. **Run with alerts:**

```bash
python crlf_scanner.py -l urls.txt \
  --telegram-token "YOUR_TOKEN" \
  -c "YOUR_CHAT_ID"
```

> [!TIP]
> Keep secrets out of shell history — use environment variables instead:
> ```bash
> export CRLF_TELEGRAM_TOKEN="YOUR_TOKEN"
> export CRLF_TELEGRAM_CHATID="YOUR_CHAT_ID"
> python crlf_scanner.py -l urls.txt
> ```

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/test-tube.png" width="22"/> &nbsp; Lab Server

A deliberately vulnerable test server is bundled so you can verify the scanner locally before pointing it at a real target.

```bash
# Terminal 1 — start the lab
python test_server.py --port 8000

# Terminal 2 — confirm detection
python crlf_scanner.py -u http://127.0.0.1:8000/vuln/test -v

# Confirm safe endpoints report clean
python crlf_scanner.py -u "http://127.0.0.1:8000/safe/redirect?url=test" -v
```

| Endpoint | Type | Vulnerability |
|:---------|:----:|:--------------|
| `/redirect?url=…` | 🔴 Vulnerable | Reflects input raw in `Location` header |
| `/setcookie?name=…` | 🔴 Vulnerable | Reflects input raw in `Set-Cookie` header |
| `/echo?header=…` | 🔴 Vulnerable | Reflects input as a custom response header |
| `/vuln/<path>` | 🔴 Vulnerable | Path-based injection via `X-Debug-Path` |
| `/safe/redirect?url=…` | 🟢 Safe | CRLF-stripped before header write |
| `/safe/cookie?name=…` | 🟢 Safe | CRLF-stripped before header write |

<br>

<!-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ -->

## <img src="https://img.icons8.com/nolan/30/conference-call.png" width="22"/> &nbsp; Contributing

Contributions, issues and feature requests are welcome!
Check the [issues page](https://github.com/0xgh0stri13y/FROST/issues) or open a PR.

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

> [!CAUTION]
> **FROST** is for **authorized security testing and education only**. Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal**. Always obtain proper authorization before scanning.

---

<div align="center">

<br>

Made with ❤️ by **[Gh0st_ri13y](https://github.com/0xgh0stri13y)**

<br>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:0d2030,100:7dd8f8&height=80&section=footer" width="100%">

</div>
