#!/usr/bin/env python3
"""
Xiaomi Unlock Assistant (Diagnostic Only)

Advanced event-driven diagnostic utility for Mi Unlock Status -> "Add account and device" failures.

Safety boundary:
- This tool does NOT unlock devices.
- This tool does NOT bypass Xiaomi restrictions.
- This tool does NOT emulate Xiaomi clients/APIs.
- This tool only captures diagnostics, parses logs, classifies likely root cause, and reports evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import math
import os
import queue
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Iterable, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

TOOL_VERSION = "2.2.1"
HISTORY_MAX_ENTRIES = 500
DEFAULT_HISTORY_WINDOW_MINUTES = 30

DEFAULT_DOMAINS = [
    "account.xiaomi.com",
    "api.io.mi.com",
    "new.c.mi.com",
    "unlock.update.miui.com",
]

# Core event regexes: any of these can act as trigger candidates.
EVENT_PATTERNS: dict[str, list[str]] = {
    "xiaomi_response_p0": [
        r"CloudDeviceStatus.*desc(?:EN|CN)",
        r'"code"\s*:\s*30003',
        r"system is being upgraded",
        r"please try again later",
        r"go to mi community to apply for authorization",
    ],
    "http_error_p1": [
        r"\bHTTP/\d\.\d\s*[45]\d\d\b",
        r"\bresponse\s*code\s*[=:]?\s*[45]\d\d\b",
    ],
    "dns_error": [
        r"UnknownHostException",
        r"unable to resolve host",
        r"Temporary failure in name resolution",
        r"Name or service not known",
    ],
    "tls_ssl_error": [
        r"SSLHandshakeException",
        r"javax\.net\.ssl",
        r"TLS handshake",
        r"CERTIFICATE_VERIFY_FAILED",
        r"certificate path",
    ],
    "timeout": [
        r"SocketTimeoutException",
        r"connect timed out",
        r"read timed out",
        r"ETIMEDOUT",
    ],
    "xiaomi_specific_event": [
        r"\bmi unlock status\b",
        r"\badd account and device\b",
        r"\bbind account\b",
        r"\baccount\.xiaomi\.com\b",
        r"\bapi\.io\.mi\.com\b",
        r"\bsystem is being upgraded\b",
        r"\bplease try again later\b",
        r"\bmi community\b",
        r"\bunlock permission\b",
    ],
}

EVENT_NOISE_PATTERNS: list[str] = [
    r"\bbinder\b",
    r"binder:",
    r"BinderProxy",
    r"binder code",
    r"\bContextImpl\b",
    r"sendBroadcastMultiplePermissions",
    r"TelephonyRegistry",
    r"ActivityManager",
    r"\bActivityThread\b",
    r"\bSystemServer\b",
    r"\bWindowManager\b",
    r"surfaceflinger",
    r"\bMI-SF\b",
    r"Choreographer",
    r"ViewRootImpl",
    r"HWComposer",
    r"HWUI",
    r"audit\(",
    r"avc:\s+denied",
    r"SELinux",
    r"\bqcc_",
    r"\bQCC:",
    r"qcc_file_agent",
    r"qccsyshal",
    r"OmaDMNative",
    r"\bQti\b",
    r"vendor\.qti",
    r"Qualcomm",
    r"\bSDM\d*\b",
    r"traffic stats poll",
    r"bandwidth estimator",
]
EVENT_NOISE_COMPILED = [re.compile(p, re.IGNORECASE) for p in EVENT_NOISE_PATTERNS]

# Classifier evidence patterns (bind and unlock-authorization are separate tracks).
CLASSIFIER_PATTERNS: dict[str, list[str]] = {
    "bind_failure_network": [
        r"UnknownHostException",
        r"unable to resolve host",
        r"Name or service not known",
        r"Temporary failure in name resolution",
        r"SSLHandshakeException",
        r"TLS handshake",
        r"connection reset",
        r"Connection refused",
        r"SocketTimeoutException",
        r"connect timed out",
        r"read timed out",
        r"network is unreachable",
    ],
    "bind_failure_server": [
        r"system is being upgraded",
        r"please try again later",
        r"maintenance",
        r"service unavailable",
        r"CloudDeviceStatus.*desc(?:EN|CN)",
        r'"code"\s*:\s*30003',
        r"HTTP/\d\.\d\s*5\d\d",
    ],
    "unlock_authorization_required": [
        r"apply.*mi community",
        r"unlock permission",
        r"unlock authorization",
        r"authorization required for unlock",
        r"unlock quota",
        r"not eligible.*unlock",
    ],
}

XIAOMI_CONTEXT_HINTS: list[str] = [
    "xiaomi",
    "mi unlock",
    "unlock status",
    "add account and device",
    "mi community",
    "account.xiaomi.com",
    "api.io.mi.com",
    "miui",
    "hyperos",
]

HTTP_MARKERS: list[str] = [
    "http/",
    "https://",
    "http://",
    "okhttp",
    "retrofit",
    "response code",
    "url=",
    "request",
    " get ",
    " post ",
]

DOMAIN_TLD_ALLOWLIST: set[str] = {
    "com",
    "net",
    "org",
    "io",
    "cn",
    "ru",
    "de",
    "uk",
    "info",
    "me",
    "xyz",
}

DOMAIN_PACKAGE_PREFIX_DENY: tuple[str, ...] = (
    "android.",
    "com.android.",
    "java.",
    "kotlin.",
    "vendor.",
)

URL_RE = re.compile(r'https?://[^\s\]\)"\'>]+', re.IGNORECASE)
HTTP_STATUS_STRICT_RE = re.compile(
    r"\bHTTP/\d\.\d\s*(\d{3})\b|\bresponse\s*code\s*[=:]?\s*(\d{3})\b|\bstatus(?:=|:)\s*(\d{3})\b",
    re.IGNORECASE,
)
STATUS_HINT_RE = re.compile(r"\bstatus(?:=|:)?\s*(\d{3})\b", re.IGNORECASE)
EXCEPTION_RE = re.compile(
    r"\b([A-Za-z0-9_$.]*(?:Exception|IOException|Error))\b"
)
HOST_FROM_ERROR_RE = [
    re.compile(r"Unable to resolve host\s+([a-z0-9.-]+)", re.IGNORECASE),
    re.compile(r"UnknownHostException:?\s*([a-z0-9.-]+)", re.IGNORECASE),
    re.compile(r"\bHost:\s*([a-z0-9.-]+)", re.IGNORECASE),
    re.compile(r"Connecting to\s+([a-z0-9.-]+)", re.IGNORECASE),
]
TOKEN_REDACT_RE = re.compile(
    r"([?&](?:token|sid|session|auth|ticket|key|signature|sig|password|passwd)=)[^&\s]+",
    re.IGNORECASE,
)
LONG_ID_RE = re.compile(r"\b[a-f0-9]{32,}\b", re.IGNORECASE)
LOGCAT_TS_RE = re.compile(r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})")
CLOUD_STATUS_JSON_RE = re.compile(
    r'CloudDeviceStatus.*?"code"\s*:\s*(?P<code>\d+).*?(?:descEN|descCN)"\s*:\s*"(?P<desc>[^"]+)"',
    re.IGNORECASE,
)
NETWORK_STACK_MARKER_RE = re.compile(
    r"okhttp|retrofit|url=|request|response|http/\d\.\d|\bGET\b|\bPOST\b",
    re.IGNORECASE,
)
SUCCESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'"code"\s*:\s*0\b', re.IGNORECASE),
    re.compile(r"\bbind(?:ing)?\b.*\bsuccess(?:ful(?:ly)?)?\b", re.IGNORECASE),
    re.compile(r"\bsuccess(?:ful(?:ly)?)?\b.*\bbind\b", re.IGNORECASE),
    re.compile(r"\b200\s*ok\b.*\bbind\b", re.IGNORECASE),
    re.compile(r"\badd account and device\b.*\bsuccess", re.IGNORECASE),
]


class ToolError(RuntimeError):
    pass


@dataclasses.dataclass
class CommandResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclasses.dataclass
class DeviceSnapshot:
    serial: str
    model: Optional[str]
    product: Optional[str]
    device: Optional[str]
    build_display_id: Optional[str]
    android_version: Optional[str]
    miui_version: Optional[str]
    hyperos_version: Optional[str]
    region: Optional[str]
    sim_state: Optional[str]
    operator_alpha: Optional[str]
    operator_numeric: Optional[str]
    dns: dict[str, Optional[str]]
    auto_time: Optional[str]
    auto_time_zone: Optional[str]
    device_epoch_s: Optional[int]
    host_epoch_s: int
    time_skew_s: Optional[int]


@dataclasses.dataclass
class DomainCheck:
    domain: str
    dns_ok: bool
    resolved_ips: list[str]
    dns_error: Optional[str]
    tls_ok: bool
    tls_error: Optional[str]
    latency_ms: Optional[int]
    tls_failure_type: Optional[str] = None


@dataclasses.dataclass
class EventRecord:
    timestamp: str
    line: str
    pattern_group: str
    regex: str
    priority: int
    score: int
    xiaomi_context: bool
    specificity: int


@dataclasses.dataclass
class LogRecord:
    timestamp: str
    line: str


@dataclasses.dataclass
class EventCaptureResult:
    total_lines: int
    trigger: Optional[EventRecord]
    context_before: list[str]
    context_after: list[str]
    all_lines: list[str]
    events: list[EventRecord]
    log_path: Optional[str]
    noise_filtered_count: int
    noise_examples: list[str]


@dataclasses.dataclass
class XiaomiJsonAggregate:
    code: str
    desc: str
    count: int
    first_seen: str
    last_seen: str


@dataclasses.dataclass
class ParsedEvidence:
    urls_redacted: list[str]
    domains_trusted: list[str]
    domains_rejected: list[str]
    http_statuses: list[int]
    non_http_status_hints: list[str]
    exceptions: list[str]
    xiaomi_related_lines: list[str]
    xiaomi_json_events: list[str]
    xiaomi_json_aggregates: list[XiaomiJsonAggregate]
    bind_success_detected: bool = False
    success_evidence: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Classification:
    label: str
    confidence: float
    root_evidence: list[str]
    confidence_explanation: list[str]
    secondary: list[str]
    secondary_label: Optional[str]
    internal_label: str
    conflict: bool
    conflict_reason: Optional[str]
    correlation_flags: list[str]
    meaning: str
    filtered_noise: list[str]
    scores: dict[str, int]
    best_score: int
    second_score: int
    confidence_floor: float
    confidence_k: int
    terminal_override_applied: bool
    terminal_override_reason: Optional[str]
    conflict_type: str = "none"
    signal_quality: str = "noisy"
    server_authority: bool = False
    layer: Literal["network", "transport", "server", "business_bind", "business_unlock", "rate_limit", "server_degradation"] = "transport"
    noise_ratio: float = 0.0
    network_state: str = "degraded"
    server_trust_level: str = "soft"
    human_why: list[str] = dataclasses.field(default_factory=list)
    truth_layer: dict[str, bool] = dataclasses.field(default_factory=dict)
    root_cause: str = "unknown"
    side_effects: list[str] = dataclasses.field(default_factory=list)
    network_profile: dict[str, str] = dataclasses.field(default_factory=dict)
    causal_graph: list[str] = dataclasses.field(default_factory=list)
    action: str = "REVIEW_LOGS"
    action_message: str = "Review evidence and retry diagnostics."
    confidence_level: str = "UNCERTAIN"
    conflict_resolution: str = "none"
    retry_after_sec: Optional[int] = None


@dataclasses.dataclass
class OptionalPhoneNetworkCheck:
    command: str
    output: str


@dataclasses.dataclass
class DiagnosisReport:
    created_at_utc: str
    tool_version: str
    serial: str
    device_snapshot: DeviceSnapshot
    host_domain_checks: list[DomainCheck]
    phone_network_checks: list[OptionalPhoneNetworkCheck]
    capture: EventCaptureResult
    parsed: ParsedEvidence
    classification: Classification
    event_flow: list[str] = dataclasses.field(default_factory=list)
    global_status: Optional[dict[str, Any]] = None


@dataclasses.dataclass
class HistoryEntry:
    ts_utc: str
    serial: str
    diagnosis: str
    confidence: float
    cloud_code: Optional[str]
    server_authority: bool
    network_signal: bool
    bind_success: bool
    conflict: bool
    signal_quality: str
    timeout_signal: bool = False
    network_ok_ratio: float = 0.0
    latency_state: str = "unknown"
    attempt_interval_sec: Optional[int] = None


@dataclasses.dataclass
class GlobalTrend:
    status: str
    confirmed_runs: int
    observed_runs: int
    duration_minutes: int
    state_transition: Optional[str]
    window_minutes: int
    trend_last5: list[str] = dataclasses.field(default_factory=list)
    trend_stability: str = "mixed"
    status_confidence: float = 0.5
    freshness_minutes: Optional[int] = None
    decay_applied: float = 0.0
    retry_hint: Optional[str] = None
    weighted_confirmed_runs: float = 0.0
    weighted_observed_runs: float = 0.0


def run_command(cmd: list[str], timeout: Optional[int] = None, check: bool = False) -> CommandResult:
    start = time.time()
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    result = CommandResult(
        cmd=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_ms=int((time.time() - start) * 1000),
    )
    if check and result.returncode != 0:
        raise ToolError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def parse_iso_utc(value: str) -> Optional[dt.datetime]:
    try:
        normalized = value.replace("Z", "+00:00")
        ts = dt.datetime.fromisoformat(normalized)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        return ts.astimezone(dt.timezone.utc)
    except Exception:
        return None


def normalize_empty(value: str) -> Optional[str]:
    v = (value or "").strip()
    if not v or v.lower() in {"unknown", "null", "none", "n/a"}:
        return None
    return v


def redact_sensitive_text(text: str) -> str:
    redacted = TOKEN_REDACT_RE.sub(r"\1<redacted>", text)
    redacted = LONG_ID_RE.sub("<id_redacted>", redacted)
    return redacted


def has_xiaomi_context(line: str) -> bool:
    low = line.lower()
    return any(hint in low for hint in XIAOMI_CONTEXT_HINTS)


def is_noise_line(line: str) -> bool:
    low = line.lower()
    matches_noise = any(rgx.search(low) for rgx in EVENT_NOISE_COMPILED)
    if not matches_noise:
        return False
    # Allow Xiaomi-specific high-signal lines through even if they contain noisy tags.
    if has_xiaomi_context(low) and (
        "clouddevicestatus" in low
        or "system is being upgraded" in low
        or "apply for authorization" in low
        or "http/" in low
    ):
        return False
    return True


def has_http_marker(line: str) -> bool:
    low = f" {line.lower()} "
    return any(marker in low for marker in HTTP_MARKERS)


def parse_http_status_from_line(line: str) -> tuple[Optional[int], bool]:
    m = HTTP_STATUS_STRICT_RE.search(line)
    if not m:
        hint = STATUS_HINT_RE.search(line)
        return None, hint is not None
    if not has_http_marker(line) and "HTTP/" not in line:
        # status=### without request/response markers is treated as non-HTTP hint.
        return None, True
    for idx in (1, 2, 3):
        grp = m.group(idx)
        if grp:
            try:
                return int(grp), False
            except ValueError:
                continue
    return None, False


def sanitize_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except Exception:
        return redact_sensitive_text(url)
    query = TOKEN_REDACT_RE.sub(r"\1<redacted>", f"?{parsed.query}").lstrip("?")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def normalize_host(raw: str) -> str:
    host = raw.strip().strip("[](){}<>,;:'\"").lower()
    if ":" in host and host.count(":") == 1:
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
    return host


def validate_domain(host: str) -> tuple[bool, str]:
    if not host or "." not in host:
        return False, "missing_dot"
    if any(host.startswith(prefix) for prefix in DOMAIN_PACKAGE_PREFIX_DENY):
        return False, "android_package_like"
    labels = host.split(".")
    if len(labels) < 2:
        return False, "invalid_label_count"
    if any(not label for label in labels):
        return False, "empty_label"
    if labels[-1].isdigit():
        return False, "numeric_tld"
    if all(re.fullmatch(r"[0-9-]+", label) for label in labels):
        return False, "numeric_like_host"
    tld = labels[-1]
    if tld not in DOMAIN_TLD_ALLOWLIST:
        return False, f"tld_not_allowed:{tld}"
    if any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return False, "invalid_characters"
    return True, "ok"


def extract_logcat_timestamp(line: str) -> str:
    m = LOGCAT_TS_RE.match(line)
    if m:
        return m.group("ts")
    return now_utc_iso()


def extract_cloud_status_key(line: str) -> Optional[tuple[str, str]]:
    m = CLOUD_STATUS_JSON_RE.search(line)
    if not m:
        return None
    code = m.group("code")
    desc = m.group("desc").strip()
    if not code or not desc:
        return None
    return code, desc


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def ansi(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def color_status(label: str) -> str:
    if "SERVER" in label:
        return "1;31"
    if "NETWORK" in label:
        return "1;33"
    if "SUCCESS" in label or "NORMAL_OPERATION" in label:
        return "1;32"
    return "1;37"


def terminal_color_enabled(no_color: bool) -> bool:
    return (not no_color) and sys.stdout.isatty()


def classify_tls_failure_type(error_text: Optional[str]) -> Optional[str]:
    if not error_text:
        return None
    low = error_text.lower()
    if (
        "unexpected eof" in low
        or "unexpected_eof" in low
        or "eof occurred in violation of protocol" in low
        or "eof while reading" in low
    ):
        return "connection_closed"
    if "certificate_verify_failed" in low or "cert" in low and "verify" in low:
        return "cert_error"
    if "handshake failure" in low or "sslv3 alert handshake failure" in low or "tlsv1 alert" in low:
        return "protocol_mismatch"
    if "timed out" in low or "timeout" in low:
        return "timeout"
    if "connection reset" in low:
        return "connection_reset"
    if "refused" in low:
        return "connection_refused"
    return "unknown_tls_error"


def evaluate_network_health(domain_checks: list["DomainCheck"]) -> dict[str, Any]:
    if not domain_checks:
        return {
            "healthy": False,
            "ok_ratio": 0.0,
            "dns_ok_ratio": 0.0,
            "tls_ok_ratio": 0.0,
            "avg_latency_ms": None,
            "latency_state": "unknown",
            "tls_severity": 0,
        }

    total = len(domain_checks)
    dns_ok_count = sum(1 for check in domain_checks if check.dns_ok)
    tls_ok_count = sum(1 for check in domain_checks if check.dns_ok and check.tls_ok)
    end_to_end_ok_count = sum(
        1
        for check in domain_checks
        if check.dns_ok and check.tls_ok and check.latency_ms is not None
    )
    latencies = [check.latency_ms for check in domain_checks if check.latency_ms is not None]
    avg_latency_ms = int(sum(latencies) / len(latencies)) if latencies else None
    tls_severity = sum(
        2 if check.tls_failure_type in {"connection_closed", "cert_error", "protocol_mismatch"}
        else 1 if check.tls_failure_type in {"timeout", "connection_reset", "connection_refused"}
        else 0
        for check in domain_checks
    )
    ok_ratio = end_to_end_ok_count / total
    dns_ok_ratio = dns_ok_count / total
    tls_ok_ratio = tls_ok_count / total

    if avg_latency_ms is None:
        latency_state = "unknown"
    elif avg_latency_ms >= 450:
        latency_state = "high"
    elif avg_latency_ms >= 180:
        latency_state = "medium"
    else:
        latency_state = "low"

    healthy = bool(
        ok_ratio >= 0.60
        or (
            dns_ok_ratio >= 0.80
            and tls_ok_ratio >= 0.60
            and (avg_latency_ms is None or avg_latency_ms < 650)
            and tls_severity <= max(1, total // 2)
        )
    )
    return {
        "healthy": healthy,
        "ok_ratio": round(ok_ratio, 2),
        "dns_ok_ratio": round(dns_ok_ratio, 2),
        "tls_ok_ratio": round(tls_ok_ratio, 2),
        "avg_latency_ms": avg_latency_ms,
        "latency_state": latency_state,
        "tls_severity": tls_severity,
    }


def is_server_response_valid(domain_checks: list["DomainCheck"]) -> bool:
    return bool(evaluate_network_health(domain_checks).get("healthy"))


LAYER_PRIORITY = {
    "server": 4,
    "rate_limit": 4,
    "server_degradation": 3,
    "business_bind": 3,
    "business_unlock": 3,
    "transport": 2,
    "network": 1,
}


def _parse_ratio_percent(value: Optional[str]) -> float:
    if not value:
        return 0.0
    try:
        return float(str(value).strip().rstrip("%")) / 100.0
    except Exception:
        return 0.0


def _dedup_keep_order(items: list[str], limit: Optional[int] = None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out


def _event_window_summary(events: list[EventRecord], window: int = 15) -> dict[str, float]:
    recent = events[-window:] if events else []
    summary = {
        "server": 0.0,
        "business": 0.0,
        "transport": 0.0,
        "network": 0.0,
        "timeout": 0.0,
        "total": float(len(recent)),
    }
    total = max(1, len(recent))
    for idx, ev in enumerate(recent):
        # Recency-weighted aggregation: newer events dominate older ones.
        decay = 0.55 + (0.45 * ((idx + 1) / total))
        group = ev.pattern_group
        if group in {"xiaomi_response_p0", "xiaomi_specific_event"}:
            summary["server"] += decay
        elif group == "http_error_p1":
            summary["transport"] += decay
        elif group == "dns_error":
            summary["network"] += decay
        elif group == "tls_ssl_error":
            summary["transport"] += decay
            summary["network"] += decay
        elif group == "timeout":
            summary["transport"] += decay
            summary["timeout"] += decay
    return summary


def _behavior_over_time(
    recent_history: Optional[list[HistoryEntry]],
    event_summary: dict[str, float],
    network_health: dict[str, Any],
) -> dict[str, Any]:
    hist = recent_history[-10:] if recent_history else []
    intervals = [x.attempt_interval_sec for x in hist if x.attempt_interval_sec is not None and x.attempt_interval_sec >= 0]
    attempt_frequency = int(sum(intervals) / len(intervals)) if intervals else None

    timeout_streak = 0
    for item in reversed(hist):
        if item.timeout_signal:
            timeout_streak += 1
        else:
            break
    if event_summary.get("timeout", 0.0) >= 1.0:
        timeout_streak += 1

    total_runs = len(hist)
    success_runs = sum(1 for x in hist if x.bind_success)
    success_ratio = (success_runs / total_runs) if total_runs > 0 else 0.0

    latency_samples = [x.latency_state for x in hist if x.latency_state in {"low", "medium", "high"}]
    current_latency = str(network_health.get("latency_state") or "unknown")
    if current_latency in {"low", "medium", "high"}:
        latency_samples.append(current_latency)
    if not latency_samples:
        latency_trend = "unknown"
    elif len(set(latency_samples[-5:])) == 1:
        latency_trend = "stable"
    else:
        latency_trend = "jittery"

    return {
        "attempt_frequency": attempt_frequency,
        "timeout_streak": timeout_streak,
        "success_ratio": round(success_ratio, 2),
        "latency_trend": latency_trend,
    }


def decide_root_cause(
    parsed: ParsedEvidence,
    classification: Classification,
    network_health: dict[str, Any],
    events: list[EventRecord],
    recent_history: Optional[list[HistoryEntry]] = None,
    global_trend: Optional[GlobalTrend] = None,
) -> Classification:
    # Stage contract:
    # - this stage owns root-cause inference from signals
    # - later policy layer may override by authoritative rules
    # - finalize stage must not change root_cause
    cls = classification
    scores = cls.scores or {}
    event_summary = _event_window_summary(events, window=15)
    has_server_truth = any(ev.code == "30003" for ev in parsed.xiaomi_json_aggregates)
    repeated_server_truth = max((ev.count for ev in parsed.xiaomi_json_aggregates if ev.code == "30003"), default=0)
    success_detected = parsed.bind_success_detected
    network_healthy = bool(network_health.get("healthy"))
    ok_ratio = float(network_health.get("ok_ratio") or 0.0)
    tls_severity = int(network_health.get("tls_severity") or 0)
    latency_state = str(network_health.get("latency_state") or "unknown")
    trend_status = global_trend.status if global_trend is not None else None
    trend_confidence = global_trend.status_confidence if global_trend is not None else 0.0
    behavior = _behavior_over_time(recent_history, event_summary, network_health)
    attempt_frequency = behavior["attempt_frequency"]
    timeout_streak = int(behavior["timeout_streak"])
    success_ratio = float(behavior["success_ratio"])
    latency_trend = behavior["latency_trend"]
    no_server_json = len(parsed.xiaomi_json_aggregates) == 0 and len(parsed.xiaomi_json_events) == 0
    timeout_present = event_summary.get("timeout", 0.0) >= 1.0 or any("timeout" in e.lower() for e in parsed.exceptions)
    frequent_attempts = attempt_frequency is not None and attempt_frequency <= 90
    rare_attempts = attempt_frequency is None or attempt_frequency >= 120
    rate_limit_signal = bool(
        timeout_present
        and timeout_streak >= 3
        and frequent_attempts
        and success_ratio <= 0.10
        and network_healthy
        and no_server_json
    )
    server_degradation_signal = bool(
        timeout_present
        and network_healthy
        and rare_attempts
        and no_server_json
        and not rate_limit_signal
        and (success_ratio > 0.0 or trend_status in {"STABLE_SERVER_FAILURE", "CONFIRMED_SERVER_MAINTENANCE", "LIKELY_SERVER_MAINTENANCE"})
    )
    network_instability_signal = bool(
        latency_trend == "jittery"
        or latency_state == "high"
        or tls_severity >= 3
        or (timeout_present and (latency_state == "high" or not network_healthy))
    )

    candidate_strengths = {
        "server": float(scores.get("bind_failure_server", 0)) + event_summary["server"] * 2 + (12 if has_server_truth else 0),
        "rate_limit": 0.0,
        "server_degradation": 0.0,
        "business_unlock": float(scores.get("unlock_authorization_required", 0)),
        "business_bind": 0.0,
        "transport": float(event_summary["transport"] * 2 + event_summary["timeout"]),
        "network": float(scores.get("bind_failure_network", 0)) + event_summary["network"] * 2,
    }
    if cls.label in {"POSSIBLE_SERVER_RATE_LIMIT", "SERVER_DEGRADED_NO_RESPONSE", "SERVER_LIMITATION"}:
        candidate_strengths["business_bind"] = max(
            candidate_strengths["business_bind"],
            float(scores.get("bind_failure_server", 0)) + 4.0,
        )
    if trend_status == "STABLE_SERVER_FAILURE":
        candidate_strengths["server"] += 6.0 + (trend_confidence * 4.0)
    elif trend_status in {"CONFIRMED_SERVER_MAINTENANCE", "LIKELY_SERVER_MAINTENANCE"}:
        candidate_strengths["server"] += 3.0 + (trend_confidence * 2.0)
    elif trend_status == "INTERMITTENT_NETWORK":
        candidate_strengths["network"] += 2.5
        candidate_strengths["transport"] += 1.5
    elif trend_status == "NORMAL":
        candidate_strengths["transport"] *= 0.92
        candidate_strengths["network"] *= 0.92
    if cls.layer in {"server", "rate_limit", "server_degradation", "business_bind", "business_unlock", "transport", "network"}:
        candidate_strengths[cls.layer] = candidate_strengths.get(cls.layer, 0.0) + 1.5
    if rate_limit_signal:
        candidate_strengths["rate_limit"] += 8.0 + (timeout_streak * 0.8)
    if server_degradation_signal:
        candidate_strengths["server_degradation"] += 7.0 + ((1.0 - success_ratio) * 2.0)
    if network_instability_signal:
        candidate_strengths["network"] += 3.0
        candidate_strengths["transport"] += 1.2

    # Hard mode switch: under stable network + silent server pattern, rate-limit should dominate
    # instead of being only another weighted competitor.
    forced_mode: Optional[str] = None
    if rate_limit_signal and network_healthy and no_server_json:
        cls.layer = "rate_limit"
        candidate_strengths["rate_limit"] += 10.0
        candidate_strengths["server"] *= 0.6
        candidate_strengths["transport"] *= 0.6
        candidate_strengths["business_bind"] *= 0.7
        cls.correlation_flags.append("rate_limit_dominant_pattern")
        forced_mode = "rate_limit"
    elif server_degradation_signal:
        cls.layer = "server_degradation"
        candidate_strengths["server_degradation"] += 8.0
        candidate_strengths["network"] *= 0.7
        cls.correlation_flags.append("server_degradation_dominant_pattern")
        forced_mode = "server_degradation"

    if success_detected and not has_server_truth:
        for layer_name in ("server", "business_bind", "transport", "network"):
            candidate_strengths[layer_name] *= 0.72
        cls.correlation_flags.append("success_signal_suppressed_errors")

    server_history_hits = 0
    network_history_hits = 0
    normal_history_hits = 0
    if recent_history:
        for idx, item in enumerate(recent_history[-10:]):
            decay = 0.55 + (0.45 * ((idx + 1) / max(1, len(recent_history[-10:]))))
            if item.diagnosis == "REAL_SERVER_MAINTENANCE" and item.server_authority:
                server_history_hits += 1
                candidate_strengths["server"] += 1.25 * decay
            elif item.diagnosis == "NETWORK_DISTORTION":
                network_history_hits += 1
                candidate_strengths["network"] += 0.85 * decay
            elif item.bind_success or item.diagnosis == "NORMAL_OPERATION":
                normal_history_hits += 1
                candidate_strengths["transport"] *= 0.98
        if server_history_hits >= 2:
            cls.correlation_flags.append("history_supports_server")
        if network_history_hits >= 2:
            cls.correlation_flags.append("history_supports_network")
        if normal_history_hits >= 2:
            cls.correlation_flags.append("history_shows_recovery")

    has_server_signal = bool(
        candidate_strengths["server"] > 0
        or candidate_strengths["rate_limit"] > 0
        or candidate_strengths["server_degradation"] > 0
        or candidate_strengths["business_bind"] > 0
        or has_server_truth
        or cls.server_authority
    )
    has_network_signal = bool(
        candidate_strengths["network"] > 0
        or candidate_strengths["transport"] > 0
        or cls.label == "NETWORK_DISTORTION"
        or network_instability_signal
    )

    if has_server_signal and network_healthy:
        cls.conflict = bool(has_network_signal)
        if cls.conflict:
            cls.conflict_type = "network_noise"
            cls.conflict_resolution = "server_overrides_network"
            cls.conflict_reason = "server signal present while network path remains healthy"
        candidate_strengths["server"] = max(candidate_strengths["server"], candidate_strengths["network"] + 1.0)
    elif has_server_signal and has_network_signal and not network_healthy:
        cls.conflict = True
        cls.conflict_type = "real_conflict"
        cls.conflict_resolution = "degrade_confidence_due_to_transport"
        cls.conflict_reason = (
            f"server signal co-exists with weak network health (ok_ratio={ok_ratio:.2f}, "
            f"tls_severity={tls_severity}, latency={latency_state})"
        )
    elif has_network_signal and not has_server_signal:
        cls.conflict = False
        cls.conflict_type = "none"
        cls.conflict_resolution = "network_primary"

    if trend_status == "STABLE_SERVER_FAILURE" and has_server_signal:
        cls.conflict = bool(has_network_signal and not network_healthy)
        cls.conflict_resolution = "trend_supports_server"

    ranked_layers = sorted(
        (
            (layer_name, strength, LAYER_PRIORITY.get(layer_name, 0))
            for layer_name, strength in candidate_strengths.items()
            if strength > 0
        ),
        key=lambda item: (item[2], item[1]),
        reverse=True,
    )
    chosen_layer = forced_mode if forced_mode is not None else (ranked_layers[0][0] if ranked_layers else cls.layer)
    cls.layer = chosen_layer

    if chosen_layer == "rate_limit":
        cls.root_cause = "rate_limit"
        cls.label = "REAL_RATE_LIMIT"
        cls.server_trust_level = "inferred"
        cls.server_authority = False
        cls.conflict = False
        cls.conflict_type = "none"
        cls.conflict_resolution = "rate_limit_mode"
        cls.conflict_reason = None
    elif chosen_layer == "server_degradation":
        cls.root_cause = "server_degradation"
        cls.server_trust_level = "inferred"
        cls.server_authority = False
        cls.label = "SERVER_DEGRADATION" if success_ratio > 0.0 else "SERVER_SILENT_DROP"
        cls.conflict = False
        cls.conflict_type = "none"
        cls.conflict_resolution = "server_degradation_mode"
        cls.conflict_reason = None
    elif chosen_layer in {"server", "business_bind"}:
        cls.root_cause = "server"
        if has_server_truth and network_healthy:
            cls.label = "REAL_SERVER_MAINTENANCE"
            cls.server_authority = True
            cls.server_trust_level = "hard"
        elif cls.label == "NETWORK_DISTORTION" and network_healthy and not parsed.xiaomi_json_events and not success_detected:
            cls.label = "POSSIBLE_SERVER_RATE_LIMIT"
            cls.server_trust_level = "inferred"
        else:
            if cls.server_trust_level == "soft":
                cls.server_trust_level = "inferred"
    elif chosen_layer == "business_unlock":
        cls.root_cause = "authorization"
        cls.label = "UNLOCK_AUTHORIZATION_REQUIRED"
    elif chosen_layer in {"transport", "network"}:
        cls.root_cause = "network"
        if cls.label not in {"NETWORK_DISTORTION", "SERVER_DEGRADED_NO_RESPONSE"}:
            cls.label = "NETWORK_DISTORTION"

    label_meaning = {
        "REAL_SERVER_MAINTENANCE": "Confirmed server-side maintenance/degradation.",
        "REAL_RATE_LIMIT": "Rate-limit/anti-abuse behavior is the most likely cause of silent timeouts.",
        "SERVER_DEGRADATION": "Server responds inconsistently under stable network conditions.",
        "SERVER_SILENT_DROP": "Server likely drops bind attempts silently without explicit Xiaomi JSON.",
        "NETWORK_DISTORTION": "Network/TLS instability likely distorts bind responses.",
        "UNLOCK_AUTHORIZATION_REQUIRED": "Unlock authorization policy blocks progression.",
    }
    if cls.label in label_meaning:
        cls.meaning = label_meaning[cls.label]

    if cls.root_cause in {"server", "rate_limit", "server_degradation"}:
        cls.truth_layer = {
            "server": True,
            "network": False,
            "device": False,
            "authorization": False,
        }
        if cls.network_state != "ok" and "network_noise" not in cls.side_effects:
            cls.side_effects.append("network_noise")
    elif cls.root_cause == "authorization":
        cls.truth_layer = {
            "server": False,
            "network": False,
            "device": False,
            "authorization": True,
        }
    elif cls.root_cause == "network":
        cls.truth_layer = {
            "server": False,
            "network": True,
            "device": False,
            "authorization": False,
        }

    chosen_strength = candidate_strengths.get(chosen_layer, 0.0)
    second_strength = ranked_layers[1][1] if len(ranked_layers) > 1 else 0.0
    base_score = chosen_strength / max(1.0, chosen_strength + second_strength + 8.0)
    layer_weight = 0.55 + (LAYER_PRIORITY.get(chosen_layer, 1) * 0.12)
    repetition_bonus = min(0.18, max(event_summary["server"], event_summary["network"], event_summary["transport"]) * 0.02)
    if repeated_server_truth >= 2:
        repetition_bonus = max(repetition_bonus, min(0.20, repeated_server_truth * 0.03))
    if server_history_hits >= 2 and cls.root_cause in {"server", "rate_limit", "server_degradation"}:
        repetition_bonus = max(repetition_bonus, min(0.18, server_history_hits * 0.03))
    if network_history_hits >= 2 and cls.root_cause == "network":
        repetition_bonus = max(repetition_bonus, min(0.14, network_history_hits * 0.02))
    if timeout_streak >= 3:
        repetition_bonus = max(repetition_bonus, min(0.16, timeout_streak * 0.025))
    noise_penalty = min(0.22, cls.noise_ratio * 0.35)
    conflict_penalty = 0.18 if cls.conflict_type == "real_conflict" else 0.08 if cls.conflict else 0.0
    success_penalty = 0.10 if success_detected and not has_server_truth else 0.0
    health_bonus = 0.06 if network_healthy and cls.root_cause in {"server", "rate_limit", "server_degradation"} else 0.04 if ok_ratio >= 0.60 else 0.0
    latency_penalty = 0.07 if latency_state == "high" and cls.root_cause not in {"server", "rate_limit", "server_degradation"} else 0.0
    tls_penalty = (
        min(0.12, tls_severity * 0.02)
        if cls.root_cause not in {"server", "rate_limit", "server_degradation"}
        else min(0.06, tls_severity * 0.01)
    )
    attempt_bonus = 0.0
    if rate_limit_signal and frequent_attempts:
        attempt_bonus = min(0.10, (90 - max(0, attempt_frequency or 90)) / 900.0 + 0.04)
    elif server_degradation_signal and rare_attempts:
        attempt_bonus = 0.05
    network_instability_penalty = (
        0.08
        if network_instability_signal and cls.root_cause not in {"server", "rate_limit", "server_degradation"}
        else 0.03 if network_instability_signal else 0.0
    )
    recalculated_confidence = clamp(
        (base_score * layer_weight)
        + repetition_bonus
        + health_bonus
        + attempt_bonus
        - noise_penalty
        - conflict_penalty
        - success_penalty
        - latency_penalty
        - tls_penalty
        - network_instability_penalty,
        0.05,
        0.99,
    )
    cls.confidence = round(clamp((0.7 * cls.confidence) + (0.3 * recalculated_confidence), 0.05, 0.99), 2)
    if cls.confidence > 0.85:
        cls.confidence_level = "CONFIRMED"
    elif cls.confidence > 0.65:
        cls.confidence_level = "LIKELY"
    else:
        cls.confidence_level = "UNCERTAIN"

    if cls.root_cause in {"server", "rate_limit", "server_degradation"}:
        if cls.label == "REAL_RATE_LIMIT":
            cls.action = "WAIT_AND_RETRY"
            cls.action_message = "Rate limit / anti-abuse likely. Pause attempts before retry."
            retry_base = 1800 if frequent_attempts else 1200
            cls.retry_after_sec = max(retry_base, (attempt_frequency or 60) * 2)
        elif cls.label in {"SERVER_DEGRADATION", "SERVER_SILENT_DROP"}:
            cls.action = "WAIT"
            cls.action_message = "Server degradation likely. Retry later on stable intervals."
            retry_base = 2100 if cls.label == "SERVER_DEGRADATION" else 2400
            cls.retry_after_sec = retry_base
        else:
            cls.action = "WAIT"
            if global_trend and global_trend.retry_hint:
                cls.action_message = global_trend.retry_hint
            else:
                cls.action_message = "Server-side issue likely. Wait and retry later."
            retry_base = 1800
            if trend_status == "STABLE_SERVER_FAILURE":
                retry_base = 3600
            elif trend_status in {"CONFIRMED_SERVER_MAINTENANCE", "LIKELY_SERVER_MAINTENANCE"}:
                retry_base = 2400
            elif server_history_hits >= 2:
                retry_base = 2700
            cls.retry_after_sec = retry_base
    elif cls.root_cause == "network":
        cls.action = "FIX_NETWORK"
        cls.action_message = "Check DNS / VPN / SIM routing and retry on a cleaner path."
        cls.retry_after_sec = None
    elif cls.root_cause == "authorization":
        cls.action = "APPLY_IN_MI_COMMUNITY"
        cls.action_message = "Unlock authorization is required in Mi Community."
        cls.retry_after_sec = None

    if "decision_engine" not in cls.correlation_flags:
        cls.correlation_flags.append("decision_engine")
    cls.network_profile["decision_ok_ratio"] = f"{int(ok_ratio * 100)}%"
    cls.network_profile["decision_tls_severity"] = str(tls_severity)
    cls.network_profile["decision_latency"] = latency_state
    cls.network_profile["decision_layer_priority"] = str(LAYER_PRIORITY.get(chosen_layer, 0))
    cls.network_profile["attempt_frequency_sec"] = str(attempt_frequency) if attempt_frequency is not None else "unknown"
    cls.network_profile["timeout_streak"] = str(timeout_streak)
    cls.network_profile["success_ratio"] = f"{int(success_ratio * 100)}%"
    cls.network_profile["latency_trend"] = latency_trend
    cls.network_profile["rate_limit_signal"] = "yes" if rate_limit_signal else "no"
    cls.network_profile["server_degradation_signal"] = "yes" if server_degradation_signal else "no"
    cls.network_profile["stage_owner"] = "decision_engine"
    cls.confidence_explanation = cls.confidence_explanation[:6] + [
        (
            f"decision_engine: layer={chosen_layer}, layer_weight={layer_weight:.2f}, "
            f"base={base_score:.2f}, repetition_bonus={repetition_bonus:.2f}, "
            f"noise_penalty={noise_penalty:.2f}, conflict_penalty={conflict_penalty:.2f}, "
            f"attempt_bonus={attempt_bonus:.2f}, net_instability_penalty={network_instability_penalty:.2f}"
        ),
        (
            f"reason: {cls.root_cause} ({'confirmed' if cls.confidence_level == 'CONFIRMED' else 'weighted'}) | "
            f"ok_ratio={ok_ratio:.2f} | tls_severity={tls_severity} | "
            f"recent_server={event_summary['server']:.2f} | recent_network={event_summary['network']:.2f} | "
            f"timeout_streak={timeout_streak} | freq={attempt_frequency if attempt_frequency is not None else 'na'}s"
        ),
    ]
    explain_why = [f"Reason: {cls.root_cause} ({'confirmed' if cls.confidence_level == 'CONFIRMED' else 'weighted'})"]
    if repeated_server_truth > 0:
        explain_why.append(f"Why: code 30003 observed {repeated_server_truth} time(s)")
    if ok_ratio > 0:
        explain_why.append(f"Why: network stable at {int(ok_ratio * 100)}% ok, latency={latency_state}, tls_severity={tls_severity}")
    if timeout_streak > 0:
        explain_why.append(f"Why: repeated timeouts ({timeout_streak}x)")
    if attempt_frequency is not None:
        explain_why.append(f"Why: attempt frequency ~ every {attempt_frequency}s")
    if rate_limit_signal:
        explain_why.append("Why: high-frequency retries + timeout streak + no server JSON -> classified as rate limit")
    elif server_degradation_signal:
        explain_why.append("Why: stable network + rare attempts + timeouts -> classified as server degradation")
    elif network_instability_signal:
        explain_why.append("Why: latency/tls instability pattern suggests network contribution")
    if server_history_hits > 0:
        explain_why.append(f"Why: history supports server diagnosis in {server_history_hits} recent run(s)")
    elif network_history_hits > 0:
        explain_why.append(f"Why: history supports network diagnosis in {network_history_hits} recent run(s)")
    if trend_status:
        explain_why.append(f"Why: global trend={trend_status} (confidence={trend_confidence:.2f})")
    cls.human_why = _dedup_keep_order(cls.human_why[:3] + [item for item in explain_why if item not in cls.human_why], limit=8)
    cls.correlation_flags = _dedup_keep_order(cls.correlation_flags, limit=16)
    cls.side_effects = _dedup_keep_order(cls.side_effects, limit=8)
    cls.confidence_explanation = _dedup_keep_order(cls.confidence_explanation, limit=10)
    return cls

# =========================
# adb_manager
# =========================


class ADBManager:
    def __init__(self, serial: Optional[str], debug: bool = False) -> None:
        self.serial = serial
        self.debug = debug
        self._require_adb()

    @staticmethod
    def _require_adb() -> None:
        if shutil.which("adb") is None:
            raise ToolError("adb not found in PATH. Install Android Platform Tools first.")

    def adb_base(self) -> list[str]:
        cmd = ["adb"]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def resolve_serial(self) -> str:
        if self.serial:
            return self.serial
        out = run_command(["adb", "devices"], timeout=10, check=True).stdout.splitlines()
        devices: list[str] = []
        for line in out[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        if not devices:
            raise ToolError("No authorized ADB device found.")
        if len(devices) > 1:
            raise ToolError(f"Multiple devices found: {', '.join(devices)}. Use --serial.")
        self.serial = devices[0]
        return self.serial

    def shell(self, cmd: str, timeout: int = 15) -> str:
        serial = self.resolve_serial()
        res = run_command(["adb", "-s", serial, "shell", cmd], timeout=timeout)
        return (res.stdout or "").strip()

    def getprop(self, prop: str) -> Optional[str]:
        return normalize_empty(self.shell(f"getprop {prop}"))

    def clear_logcat(self) -> None:
        serial = self.resolve_serial()
        run_command(["adb", "-s", serial, "logcat", "-c"], timeout=10)


# =========================
# diagnostics (device + network)
# =========================


def _to_int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value.strip())
    except Exception:
        return None


def collect_device_snapshot(adb: ADBManager) -> DeviceSnapshot:
    serial = adb.resolve_serial()

    model = adb.getprop("ro.product.model")
    product = adb.getprop("ro.product.product.name") or adb.getprop("ro.product.name")
    device = adb.getprop("ro.product.device")
    build_display_id = adb.getprop("ro.build.display.id")
    android_version = adb.getprop("ro.build.version.release")
    miui_version = adb.getprop("ro.miui.ui.version.name")
    hyperos_version = adb.getprop("ro.mi.os.version.name") or adb.getprop("ro.mi.os.version.incremental")
    region = adb.getprop("ro.miui.region") or adb.getprop("ro.boot.hwc")
    sim_state = adb.getprop("gsm.sim.state")
    operator_alpha = adb.getprop("gsm.operator.alpha")
    operator_numeric = adb.getprop("gsm.operator.numeric")

    dns = {
        "dns1": adb.getprop("net.dns1"),
        "dns2": adb.getprop("net.dns2"),
        "dns3": adb.getprop("net.dns3"),
        "dns4": adb.getprop("net.dns4"),
    }

    auto_time = None
    auto_time_zone = None
    device_epoch = None

    try:
        auto_time = normalize_empty(adb.shell("settings get global auto_time"))
    except Exception:
        pass
    try:
        auto_time_zone = normalize_empty(adb.shell("settings get global auto_time_zone"))
    except Exception:
        pass
    try:
        device_epoch = _to_int_or_none(adb.shell("date +%s"))
    except Exception:
        pass

    host_epoch = int(time.time())
    skew = None if device_epoch is None else device_epoch - host_epoch

    return DeviceSnapshot(
        serial=serial,
        model=model,
        product=product,
        device=device,
        build_display_id=build_display_id,
        android_version=android_version,
        miui_version=miui_version,
        hyperos_version=hyperos_version,
        region=region,
        sim_state=sim_state,
        operator_alpha=operator_alpha,
        operator_numeric=operator_numeric,
        dns=dns,
        auto_time=auto_time,
        auto_time_zone=auto_time_zone,
        device_epoch_s=device_epoch,
        host_epoch_s=host_epoch,
        time_skew_s=skew,
    )


def check_domain_tls(domain: str, timeout_s: float = 5.0) -> DomainCheck:
    resolved_ips: list[str] = []
    dns_ok = False
    dns_error: Optional[str] = None
    tls_ok = False
    tls_error: Optional[str] = None
    tls_failure_type: Optional[str] = None
    latency_ms: Optional[int] = None

    infos: list[tuple[Any, Any, Any, Any, Any]] = []
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        dns_ok = True
        for info in infos:
            ip = info[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
    except Exception as exc:
        dns_error = str(exc)

    last_exc: Optional[Exception] = None
    for info in infos[:4]:
        family, socktype, proto, _canonname, sockaddr = info
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout_s)
        start = time.time()
        try:
            sock.connect(sockaddr)
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=domain) as wrapped:
                wrapped.do_handshake()
            tls_ok = True
            latency_ms = int((time.time() - start) * 1000)
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
        finally:
            try:
                sock.close()
            except Exception:
                pass

    if not tls_ok and last_exc is not None:
        tls_error = str(last_exc)
        tls_failure_type = classify_tls_failure_type(tls_error)

    return DomainCheck(
        domain=domain,
        dns_ok=dns_ok,
        resolved_ips=resolved_ips,
        dns_error=dns_error,
        tls_ok=tls_ok,
        tls_error=tls_error,
        latency_ms=latency_ms,
        tls_failure_type=tls_failure_type,
    )


def host_network_checks(domains: Iterable[str]) -> list[DomainCheck]:
    results: list[DomainCheck] = []
    for domain in domains:
        results.append(check_domain_tls(domain))
    return results


def phone_optional_network_checks(adb: ADBManager, domains: Iterable[str]) -> list[OptionalPhoneNetworkCheck]:
    checks: list[OptionalPhoneNetworkCheck] = []
    for domain in domains:
        for cmd in [f"ping -c 1 -W 2 {domain}", f"nslookup {domain}"]:
            try:
                out = adb.shell(cmd, timeout=8)
                checks.append(OptionalPhoneNetworkCheck(command=cmd, output=out[:1500]))
            except Exception as exc:
                checks.append(OptionalPhoneNetworkCheck(command=cmd, output=f"failed: {exc}"))
    return checks


# =========================
# event_detector + logcat_streamer
# =========================


class EventDetector:
    def __init__(self, patterns: dict[str, list[str]]) -> None:
        self.compiled: list[tuple[str, re.Pattern[str], str]] = []
        for group, pats in patterns.items():
            for raw in pats:
                self.compiled.append((group, re.compile(raw, re.IGNORECASE), raw))
        self.high_priority_groups = {"xiaomi_response_p0", "http_error_p1"}

    def is_noise(self, line: str) -> bool:
        return is_noise_line(line)

    def _score_candidate(self, group: str, line: str) -> tuple[int, int, int, bool]:
        low = line.lower()
        xiaomi_ctx = has_xiaomi_context(line)

        if group == "xiaomi_response_p0":
            score = 95
            specificity = 2
            if '"code":30003' in low or '"code": 30003' in low:
                score = 100
                specificity = 3
            if "apply for authorization" in low:
                score = max(score, 98)
            if any(token in low for token in ["unknownhostexception", "sslhandshakeexception", "timed out", "unexpected eof"]):
                score = min(score, 70)
            return 0, score, specificity, True

        if group == "http_error_p1":
            code, _hint = parse_http_status_from_line(line)
            if code is None:
                return 3, 0, 0, xiaomi_ctx
            if code in (401, 403):
                if xiaomi_ctx:
                    return 1, 84, 2, True
                return 3, 0, 0, False
            if 500 <= code <= 599:
                return (1, 86, 2, True) if xiaomi_ctx else (2, 72, 1, False)
            if 400 <= code <= 499:
                return (2, 60, 1, True) if xiaomi_ctx else (3, 0, 0, False)
            return 3, 0, 0, False

        if group in {"dns_error", "tls_ssl_error", "timeout"}:
            base = 70 if group != "timeout" else 66
            if xiaomi_ctx:
                base += 6
            specificity = 2 if xiaomi_ctx else 1
            return 2, base, specificity, xiaomi_ctx

        if group == "xiaomi_specific_event":
            return 3, 40, 1, xiaomi_ctx

        return 3, 0, 0, xiaomi_ctx

    def detect(self, line: str) -> Optional[EventRecord]:
        best: Optional[EventRecord] = None
        line_is_noise = self.is_noise(line)
        for group, regex, raw in self.compiled:
            if not regex.search(line):
                continue
            priority, score, specificity, xiaomi_ctx = self._score_candidate(group, line)
            if score <= 0:
                continue
            # Trigger contract: noise lines are allowed only for P0/P1 and Xiaomi-contextual events.
            if line_is_noise and not (priority <= 1 and xiaomi_ctx and group in self.high_priority_groups):
                continue
            candidate = EventRecord(
                timestamp=now_utc_iso(),
                line=redact_sensitive_text(line.rstrip("\n")),
                pattern_group=group,
                regex=raw,
                priority=priority,
                score=score,
                xiaomi_context=xiaomi_ctx,
                specificity=specificity,
            )
            if best is None:
                best = candidate
                continue
            if candidate.score > best.score:
                best = candidate
                continue
            if candidate.score == best.score and candidate.priority < best.priority:
                best = candidate
                continue
            if candidate.score == best.score and candidate.priority == best.priority:
                if candidate.xiaomi_context and not best.xiaomi_context:
                    best = candidate
                    continue
                if candidate.specificity > best.specificity:
                    best = candidate
        return best


class LogcatStreamer:
    def __init__(self, adb: ADBManager, debug: bool = False) -> None:
        self.adb = adb
        self.debug = debug

    def _build_proc(self) -> subprocess.Popen[str]:
        serial = self.adb.resolve_serial()
        cmd = ["adb", "-s", serial, "logcat", "-v", "threadtime"]
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def capture_event_driven(
        self,
        detector: EventDetector,
        duration_s: int,
        pre_seconds: int,
        post_seconds: int,
        output_path: Optional[Path],
        stop_on_trigger_score: int = 90,
        announce_ready: bool = False,
        color_enabled: bool = True,
    ) -> EventCaptureResult:
        if pre_seconds < 1:
            pre_seconds = 1
        if post_seconds < 1:
            post_seconds = 1

        # Time-based ring buffer for deterministic pre-context in seconds.
        ring: Deque[tuple[float, str]] = deque()

        proc = self._build_proc()
        if proc.stdout is None:
            raise ToolError("Failed to read adb logcat stdout")

        q: queue.Queue[str] = queue.Queue()
        stop_reader = threading.Event()

        def reader() -> None:
            try:
                for line in iter(proc.stdout.readline, ""):
                    if stop_reader.is_set():
                        break
                    if line:
                        q.put(line)
            finally:
                try:
                    if proc.stdout:
                        proc.stdout.close()
                except Exception:
                    pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        started_at = time.time()
        end_at = started_at + duration_s

        trigger: Optional[EventRecord] = None
        events: list[EventRecord] = []
        filtered_lines: Deque[str] = deque(maxlen=max(2000, pre_seconds * 250 + post_seconds * 250))
        pre_event_lines: list[str] = []
        trigger_after_lines: list[str] = []
        noise_filtered_count = 0
        noise_examples: list[str] = []
        collect_after_until: Optional[float] = None
        armed_at: Optional[float] = None

        def remember_ring(raw_line: str) -> None:
            now_mono = time.monotonic()
            ring.append((now_mono, raw_line))
            while ring and (now_mono - ring[0][0]) > pre_seconds:
                ring.popleft()

        fout = None
        try:
            if output_path is not None:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                fout = output_path.open("w", encoding="utf-8", errors="replace")

            # Warm-up / arming phase to reduce startup latency misses.
            warm_deadline = time.time() + 1.0
            while time.time() < warm_deadline:
                try:
                    warm_line = q.get(timeout=0.1)
                except queue.Empty:
                    continue
                warm_stripped = warm_line.rstrip("\n")
                remember_ring(warm_stripped)
                if fout is not None:
                    fout.write(warm_line)
                break
            if announce_ready:
                print(ansi("READY - tap 'Add account and device' now.", "1;32", color_enabled))
            armed_at = time.time()

            while time.time() < end_at:
                try:
                    line = q.get(timeout=0.25)
                except queue.Empty:
                    if collect_after_until and time.time() >= collect_after_until:
                        break
                    continue

                stripped = line.rstrip("\n")
                remember_ring(stripped)

                if fout is not None:
                    fout.write(line)

                line_is_noise = detector.is_noise(stripped)
                if line_is_noise:
                    noise_filtered_count += 1
                    if len(noise_examples) < 8:
                        noise_examples.append(redact_sensitive_text(stripped))
                else:
                    filtered_lines.append(redact_sensitive_text(stripped))

                just_updated_trigger = False
                hit = detector.detect(stripped)
                if hit:
                    if len(events) >= 200:
                        events.pop(0)
                    events.append(hit)
                    if hit.priority < 3 and (
                        trigger is None
                        or hit.score > trigger.score
                        or (hit.score == trigger.score and hit.priority < trigger.priority)
                        or (
                            trigger is not None
                            and hit.score == trigger.score
                            and hit.priority == trigger.priority
                            and hit.xiaomi_context
                            and not trigger.xiaomi_context
                        )
                        or (
                            trigger is not None
                            and hit.score == trigger.score
                            and hit.priority == trigger.priority
                            and hit.specificity > trigger.specificity
                        )
                    ):
                        trigger = hit
                        pre_event_lines = [redact_sensitive_text(rec[1]) for rec in ring]
                        trigger_after_lines = []
                        just_updated_trigger = True
                    if hit.priority == 0 or hit.score >= stop_on_trigger_score:
                        collect_after_until = time.time() + post_seconds

                if trigger is not None and not just_updated_trigger:
                    if len(trigger_after_lines) < 400:
                        trigger_after_lines.append(redact_sensitive_text(stripped))

                if collect_after_until is not None and time.time() >= collect_after_until:
                    break

                # If arming happened very late, enforce remaining timeout from arm point.
                if armed_at is not None and (time.time() - armed_at) >= duration_s:
                    break
        finally:
            stop_reader.set()
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

            while True:
                try:
                    line = q.get_nowait()
                except queue.Empty:
                    break
                if fout is not None:
                    fout.write(line)

            if fout is not None and proc.stderr is not None:
                err = proc.stderr.read()
                if err:
                    fout.write("\n# adb logcat stderr\n")
                    fout.write(err)
            if fout is not None:
                fout.close()

        context_before: list[str] = []
        context_after: list[str] = []

        if trigger:
            if pre_event_lines:
                # Ring-buffer context captured immediately at trigger time.
                context_before = pre_event_lines[-21:-1] if len(pre_event_lines) > 1 else []
            context_after = trigger_after_lines[:20]

        return EventCaptureResult(
            total_lines=len(filtered_lines),
            trigger=trigger,
            context_before=context_before,
            context_after=context_after,
            all_lines=list(filtered_lines),
            events=events,
            log_path=str(output_path) if output_path is not None else None,
            noise_filtered_count=noise_filtered_count,
            noise_examples=noise_examples,
        )


# =========================
# parser
# =========================


def parse_evidence(lines: Iterable[str]) -> ParsedEvidence:
    urls: set[str] = set()
    domains_trusted: set[str] = set()
    domains_rejected: dict[str, str] = {}
    statuses: list[int] = []
    non_http_hints: list[str] = []
    exceptions: list[str] = []
    xiaomi_lines: list[str] = []
    xiaomi_json_events: list[str] = []
    xiaomi_json_map: dict[tuple[str, str], XiaomiJsonAggregate] = {}
    success_evidence: list[str] = []

    def _collect_domain(candidate: str) -> None:
        host = normalize_host(candidate)
        ok, reason = validate_domain(host)
        if ok:
            domains_trusted.add(host)
        elif "." in host and host not in domains_rejected and len(domains_rejected) < 60:
            domains_rejected[host] = reason

    for line in lines:
        redacted_line = redact_sensitive_text(line)
        has_host_pattern = any(rgx.search(line) for rgx in HOST_FROM_ERROR_RE)
        line_has_network_or_xiaomi_ctx = bool(NETWORK_STACK_MARKER_RE.search(line)) or has_xiaomi_context(line) or has_host_pattern

        if line_has_network_or_xiaomi_ctx:
            for url in URL_RE.findall(redacted_line):
                safe_url = sanitize_url(url)
                urls.add(safe_url)
                try:
                    parsed = urlsplit(url)
                    if parsed.hostname:
                        _collect_domain(parsed.hostname)
                except Exception:
                    pass

            for rgx in HOST_FROM_ERROR_RE:
                for m in rgx.finditer(line):
                    _collect_domain(m.group(1))

        status_code, non_http_hint = parse_http_status_from_line(line)
        if status_code is not None:
            statuses.append(status_code)
        elif non_http_hint and len(non_http_hints) < 30:
            non_http_hints.append(redacted_line[:180])

        for ex in EXCEPTION_RE.findall(line):
            exceptions.append(ex)

        ll = line.lower()
        if has_xiaomi_context(line) or "try again later" in ll or "system is being upgraded" in ll:
            xiaomi_lines.append(redacted_line)
        if (
            any(rgx.search(line) for rgx in SUCCESS_PATTERNS)
            and (has_xiaomi_context(line) or bool(NETWORK_STACK_MARKER_RE.search(line)))
        ):
            if len(success_evidence) < 20:
                success_evidence.append(redacted_line[:240])
        key = extract_cloud_status_key(line)
        if key is not None:
            code, desc = key
            ts = extract_logcat_timestamp(line)
            existing = xiaomi_json_map.get((code, desc))
            if existing is None:
                xiaomi_json_map[(code, desc)] = XiaomiJsonAggregate(
                    code=code,
                    desc=desc,
                    count=1,
                    first_seen=ts,
                    last_seen=ts,
                )
            else:
                existing.count += 1
                existing.last_seen = ts
        if "clouddevicestatus" in ll and '"code"' in ll:
            xiaomi_json_events.append(redacted_line)

    uniq_exceptions = sorted(set(exceptions))
    rejected_pretty = [f"{host} ({reason})" for host, reason in domains_rejected.items()]

    return ParsedEvidence(
        urls_redacted=sorted(urls),
        domains_trusted=sorted(domains_trusted),
        domains_rejected=rejected_pretty,
        http_statuses=statuses,
        non_http_status_hints=non_http_hints,
        exceptions=uniq_exceptions,
        xiaomi_related_lines=xiaomi_lines[-120:],
        xiaomi_json_events=xiaomi_json_events[-40:],
        xiaomi_json_aggregates=sorted(
            xiaomi_json_map.values(),
            key=lambda x: (x.count, x.code),
            reverse=True,
        ),
        bind_success_detected=bool(success_evidence) or any(agg.code == "0" for agg in xiaomi_json_map.values()),
        success_evidence=success_evidence,
    )


# =========================
# classifier
# =========================


class Classifier:
    def __init__(self) -> None:
        self.compiled = {key: [re.compile(p, re.IGNORECASE) for p in pats] for key, pats in CLASSIFIER_PATTERNS.items()}
        self.maintenance_re = re.compile(r"system is being upgraded|try again later|maintenance", re.IGNORECASE)
        self.auth_strong_re = re.compile(r"go to mi community to apply for authorization", re.IGNORECASE)
        self.auth_generic_re = re.compile(
            r"unlock permission|apply for unlocking|permission required|authorization required for unlock|unlock quota",
            re.IGNORECASE,
        )
        self.dns_re = re.compile(r"UnknownHostException|unable to resolve host|name or service not known|temporary failure in name resolution", re.IGNORECASE)
        self.tls_re = re.compile(r"SSLHandshakeException|TLS handshake|CERTIFICATE_VERIFY_FAILED|certificate path|javax\.net\.ssl", re.IGNORECASE)
        self.timeout_re = re.compile(r"SocketTimeoutException|connect timed out|read timed out|ETIMEDOUT|timeout", re.IGNORECASE)

    def _has_xiaomi_context_near(self, lines: list[str], index: int, window: int = 2) -> bool:
        start = max(0, index - window)
        end = min(len(lines), index + window + 1)
        return any(has_xiaomi_context(lines[i]) for i in range(start, end))

    @staticmethod
    def _dedup_keep_order(items: list[str], limit: int = 12) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _sim_summary(sim_state: Optional[str]) -> tuple[bool, bool]:
        if not sim_state:
            return False, False
        tokens = [t.strip().lower() for t in re.split(r"[,;|/ ]+", sim_state) if t.strip()]
        if not tokens:
            return False, False
        active = any(t in {"loaded", "ready"} for t in tokens)
        all_absent_unready = all(t in {"absent", "not_ready", "unknown", "notready"} for t in tokens)
        return active, all_absent_unready

    @staticmethod
    def _suggest_action(
        root_cause: str,
        public_label: str,
        internal_label: str,
        network_state: str,
        global_status_hint: Optional[str] = None,
    ) -> tuple[str, str, Optional[int]]:
        if public_label == "NORMAL_OPERATION":
            return ("SUCCESS", "Bind operation looks healthy in this capture.", None)
        if public_label == "REAL_SERVER_MAINTENANCE":
            return ("WAIT", "Xiaomi servers under maintenance. Retry in 30-60 minutes.", random.randint(1200, 3600))
        if public_label == "SERVER_DEGRADED_NO_RESPONSE":
            return ("RETRY_LATER", "Server not responding properly. Try again soon.", random.randint(60, 300))
        if internal_label == "unlock_authorization_required" or root_cause == "authorization":
            return ("APPLY_IN_MI_COMMUNITY", "Open Mi Community and apply for unlock authorization/eligibility.", None)
        if root_cause == "server":
            return ("WAIT_AND_RETRY_LATER", "Wait 30-60 minutes and retry bind once.", random.randint(1200, 3600))
        if root_cause == "network":
            if network_state == "failing":
                return ("FIX_NETWORK", "Check DNS/VPN/SIM path and retry on another Wi-Fi or mobile network.", None)
            return ("STABILIZE_NETWORK", "Retry on a more stable connection; avoid VPN/proxy/DPI paths and verify SIM/network routing.", random.randint(60, 300))
        if root_cause == "device":
            return ("VERIFY_DEVICE_STATE", "Check SIM/operator/region/time settings and retry bind.", None)
        if global_status_hint == "STATE_TRANSITION_MAINTENANCE_TO_OK":
            return ("RETRY_NOW", "Server likely recovered; retry bind now.", 30)
        return ("REVIEW_LOGS", "Collect another run to increase confidence.", None)

    @staticmethod
    def _aggregation_bonus(count: int) -> int:
        if count >= 5:
            return 12
        if count >= 3:
            return 10
        if count >= 2:
            return 6
        return 0

    def classify(
        self,
        capture: EventCaptureResult,
        parsed: ParsedEvidence,
        domain_checks: list[DomainCheck],
        snapshot: DeviceSnapshot,
        phone_checks: Optional[list[OptionalPhoneNetworkCheck]] = None,
    ) -> Classification:
        signal_weights = {
            "server": 1.35,
            "business": 1.15,
            "transport": 1.0,
            "network": 0.95,
            "success": -0.75,
            "noise_penalty": -0.60,
        }
        scores = {
            "bind_failure_network": 0,
            "bind_failure_server": 0,
            "bind_failure_account_state": 0,
            "unlock_authorization_required": 0,
        }
        evidence: dict[str, list[str]] = {k: [] for k in scores}
        score_notes: list[tuple[str, int, str]] = []
        secondary: list[str] = []
        terminal_override_applied = False
        terminal_override_reason: Optional[str] = None
        conflict = False
        conflict_reason: Optional[str] = None
        correlation_flags: list[str] = []

        scan_lines = capture.all_lines
        recent_events = capture.events[-15:]

        def add_score(label: str, points: int, note: str) -> None:
            if points <= 0:
                return
            scores[label] += points
            evidence[label].append(note)
            score_notes.append((label, points, note))

        seen_cloud_keys: set[tuple[str, str]] = set()
        ctx_dns_hits = 0
        ctx_tls_hits = 0
        ctx_timeout_hits = 0
        non_ctx_dns_hits = 0
        non_ctx_tls_hits = 0
        non_ctx_timeout_hits = 0

        for idx, line in enumerate(scan_lines):
            ctx = self._has_xiaomi_context_near(scan_lines, idx)
            low = line.lower()
            cloud_key = extract_cloud_status_key(line)

            if cloud_key is not None and cloud_key not in seen_cloud_keys:
                seen_cloud_keys.add(cloud_key)
                code, desc = cloud_key
                target = "unlock_authorization_required" if "apply for authorization" in desc.lower() else "bind_failure_server"
                add_score(target, 12, f'+12 {"authorization" if target=="unlock_authorization_required" else "server"}: Xiaomi JSON CloudDeviceStatus(code={code}, desc="{desc[:120]}")')

            if self.maintenance_re.search(line) and (ctx or cloud_key is not None):
                add_score("bind_failure_server", 10, '+10 server: explicit maintenance phrase in Xiaomi context')

            if self.auth_strong_re.search(line):
                add_score("unlock_authorization_required", 12, "+12 authorization: explicit Mi Community authorization message")
            elif self.auth_generic_re.search(line):
                if ctx:
                    add_score("unlock_authorization_required", 8, "+8 authorization: unlock permission phrase with Xiaomi context")
                else:
                    secondary.append(f"Ignored authorization phrase without Xiaomi context: {line[:120]}")

            status_code, non_http_hint = parse_http_status_from_line(line)
            if status_code is not None:
                if 500 <= status_code <= 599:
                    add_score(
                        "bind_failure_server",
                        7 if ctx else 3,
                        f'+{7 if ctx else 3} server: HTTP {status_code} {"with" if ctx else "without"} Xiaomi context',
                    )
                if status_code in (401, 403):
                    if ctx:
                        add_score("unlock_authorization_required", 7, f"+7 authorization: HTTP {status_code} with Xiaomi context")
                    else:
                        secondary.append(f"Ignored HTTP {status_code} without Xiaomi context")
            elif non_http_hint:
                secondary.append(f"Non-HTTP status hint ignored: {line[:120]}")

            if self.dns_re.search(line):
                if ctx:
                    ctx_dns_hits += 1
                else:
                    non_ctx_dns_hits += 1
                add_score("bind_failure_network", 9 if ctx else 6, f'+{9 if ctx else 6} network: DNS resolution failure {"with" if ctx else "without"} Xiaomi context')
            if self.tls_re.search(line):
                if ctx:
                    ctx_tls_hits += 1
                else:
                    non_ctx_tls_hits += 1
                add_score("bind_failure_network", 9 if ctx else 6, f'+{9 if ctx else 6} network: TLS/SSL failure {"with" if ctx else "without"} Xiaomi context')
            if self.timeout_re.search(line):
                if ctx:
                    ctx_timeout_hits += 1
                else:
                    non_ctx_timeout_hits += 1
                add_score("bind_failure_network", 7 if ctx else 4, f'+{7 if ctx else 4} network: timeout {"with" if ctx else "without"} Xiaomi context')

            if ctx and EXCEPTION_RE.search(line) and NETWORK_STACK_MARKER_RE.search(low):
                add_score("bind_failure_network", 2, "+2 network: exception with Xiaomi/network stack markers")

        recent_server_events = sum(1 for ev in recent_events if "xiaomi_response" in ev.pattern_group or "xiaomi" in ev.pattern_group)
        recent_timeout_events = sum(1 for ev in recent_events if "timeout" in ev.pattern_group)
        recent_transport_events = sum(1 for ev in recent_events if ev.pattern_group in {"http_error_p1", "tls_ssl_error", "dns_error"})
        if recent_server_events >= 2:
            points = min(8, int((recent_server_events + 1) * signal_weights["server"]))
            add_score("bind_failure_server", points, f"+{points} server_window: repeated Xiaomi/server events in recent window ({recent_server_events}/15)")
        if recent_timeout_events >= 3:
            points = min(6, int(recent_timeout_events * signal_weights["transport"]))
            add_score("bind_failure_network", points, f"+{points} transport_window: repeated timeout events in recent window ({recent_timeout_events}/15)")
        if recent_transport_events >= 3:
            points = min(5, int(recent_transport_events * signal_weights["transport"]))
            add_score("bind_failure_network", points, f"+{points} transport_window: repeated DNS/TLS/HTTP anomalies in recent window ({recent_transport_events}/15)")

        for agg in parsed.xiaomi_json_aggregates:
            bonus = self._aggregation_bonus(agg.count)
            if bonus <= 0:
                continue
            target = "unlock_authorization_required" if "apply for authorization" in agg.desc.lower() else "bind_failure_server"
            add_score(
                target,
                bonus,
                f"+{bonus} {'authorization' if target=='unlock_authorization_required' else 'server'}: repeated Xiaomi response x{agg.count} ({agg.first_seen}..{agg.last_seen})",
            )

        net_health = evaluate_network_health(domain_checks)
        dns_fail_count = sum(1 for d in domain_checks if not d.dns_ok)
        tls_fail_count = sum(1 for d in domain_checks if d.dns_ok and not d.tls_ok)
        if dns_fail_count > 0:
            add_score("bind_failure_network", min(6, dns_fail_count * 2), f"+{min(6, dns_fail_count * 2)} network: PC DNS checks failed ({dns_fail_count} domain(s))")
        if tls_fail_count > 0:
            add_score("bind_failure_network", min(6, tls_fail_count * 2), f"+{min(6, tls_fail_count * 2)} network: PC TLS checks failed ({tls_fail_count} domain(s))")
        if net_health["ok_ratio"] >= 0.60:
            secondary.append(
                f"Network majority check passed ({int(net_health['ok_ratio'] * 100)}% domains healthy, latency={net_health['latency_state']})."
            )

        if phone_checks:
            phone_fail = 0
            for check in phone_checks:
                low = check.output.lower()
                if any(token in low for token in ["unknown host", "can't resolve", "temporary failure", "timed out", "ssl", "tls"]):
                    phone_fail += 1
            if phone_fail > 0:
                phone_points = min(6, phone_fail * 3)
                add_score("bind_failure_network", phone_points, f"+{phone_points} network: phone-side DNS/TLS/timeout checks failed ({phone_fail})")

        sim_active, all_absent_unready = self._sim_summary(snapshot.sim_state)
        operator_present = bool(snapshot.operator_alpha or snapshot.operator_numeric)
        if all_absent_unready and not operator_present:
            add_score("bind_failure_account_state", 4, "+4 account_state: no active SIM and operator is empty")

        account_time_points = 0
        if snapshot.time_skew_s is not None and abs(snapshot.time_skew_s) > 300:
            account_time_points += 2
        if snapshot.auto_time not in {None, "1"}:
            account_time_points += 2
        if account_time_points > 0:
            capped = min(2, account_time_points)
            add_score("bind_failure_account_state", capped, f"+{capped} account_state: time skew / auto_time weakness")

        # LOADED,ABSENT should not be penalized.
        if sim_active and snapshot.sim_state and "absent" in snapshot.sim_state.lower():
            secondary.append("SIM state includes ABSENT in one slot, but another slot is active (treated as normal dual-SIM case).")

        terminal_target: Optional[str] = None
        if capture.trigger is not None and capture.trigger.priority == 0:
            trig_low = capture.trigger.line.lower()
            if "apply for authorization" in trig_low or "mi community" in trig_low:
                terminal_target = "unlock_authorization_required"
                terminal_override_reason = "terminal authorization P0 event detected"
            elif ('"code":30003' in trig_low) or ("system is being upgraded" in trig_low):
                terminal_target = "bind_failure_server"
                terminal_override_reason = "terminal server P0 event detected (CloudDeviceStatus/30003/maintenance)"

        # Backup terminal detection from aggregated Xiaomi JSON.
        if terminal_target is None:
            for agg in parsed.xiaomi_json_aggregates:
                desc_low = agg.desc.lower()
                if agg.code == "30003" or "system is being upgraded" in desc_low:
                    terminal_target = "bind_failure_server"
                    terminal_override_reason = "terminal server signal from aggregated Xiaomi JSON"
                    break
                if "apply for authorization" in desc_low or "mi community" in desc_low:
                    terminal_target = "unlock_authorization_required"
                    terminal_override_reason = "terminal authorization signal from aggregated Xiaomi JSON"
                    break

        tls_suspicious_count = sum(
            1
            for d in domain_checks
            if d.tls_failure_type in {"connection_closed", "protocol_mismatch", "cert_error", "timeout", "connection_reset"}
        )
        tls_suspicion_points = sum(
            2 if d.tls_failure_type == "connection_closed"
            else 1 if d.tls_failure_type in {"protocol_mismatch", "cert_error"}
            else 0
            for d in domain_checks
        )
        server_response_valid = net_health["healthy"]
        has_code_30003 = any(agg.code == "30003" for agg in parsed.xiaomi_json_aggregates) or (
            capture.trigger is not None and '"code":30003' in capture.trigger.line.lower()
        )
        repeated_30003_count = max((agg.count for agg in parsed.xiaomi_json_aggregates if agg.code == "30003"), default=0)
        has_transport_path_issue = (
            dns_fail_count > 0
            or tls_fail_count > 0
            or tls_suspicious_count > 0
        )
        server_signal_present = scores["bind_failure_server"] > 0
        raw_network_score = scores["bind_failure_network"]
        network_signal_present = raw_network_score > 0
        if server_signal_present and raw_network_score > 0:
            suppressed = max(1, int(raw_network_score * 0.3))
            if suppressed < raw_network_score:
                scores["bind_failure_network"] = suppressed
                secondary.append(
                    f"Server signal present: network score suppressed {raw_network_score} -> {suppressed} (server-priority rule)."
                )
        if parsed.bind_success_detected:
            for label in ("bind_failure_network", "bind_failure_server", "bind_failure_account_state"):
                original = scores[label]
                softened = max(0, int(original * (1.0 + signal_weights["success"] * 0.35)))
                if softened < original:
                    scores[label] = softened
                    secondary.append(f"Success evidence reduced {label} score {original} -> {softened}.")
        authorization_signal_present = scores["unlock_authorization_required"] > 0
        if server_signal_present:
            correlation_flags.append("server_signal_strong")
        if network_signal_present:
            correlation_flags.append("network_noise_present")
        if server_signal_present and network_signal_present:
            conflict = True
            correlation_flags.append("ambiguous_environment")
            if conflict_reason is None:
                conflict_reason = "server and network signals are present simultaneously"
        flow_steps = summarize_event_flow(capture.events)
        unstable_flow = False
        for i in range(len(flow_steps) - 2):
            if flow_steps[i] == "timeout" and flow_steps[i + 1] == "xiaomi_response" and flow_steps[i + 2] == "timeout":
                unstable_flow = True
                break
        if unstable_flow:
            correlation_flags.append("unstable_network_flow")
            secondary.append("Event flow suggests unstable network (timeout -> response -> timeout).")
        jitter_state = classify_latency_jitter(domain_checks)
        timeout_hits_total = ctx_timeout_hits + non_ctx_timeout_hits
        if dns_fail_count > 0 or tls_fail_count > 0:
            network_state = "failing"
        elif timeout_hits_total > 0 or jitter_state == "high" or network_signal_present or unstable_flow or net_health["latency_state"] == "high":
            network_state = "degraded"
        else:
            network_state = "stable"

        # Suppress network dominance when terminal server event is present, but only on clean transport.
        if terminal_target == "bind_failure_server":
            if has_transport_path_issue or not server_response_valid:
                conflict = True
                conflict_reason = (
                    "ambiguous_server_response: terminal server signal co-exists with transport issues "
                    f"(dns_fail={dns_fail_count}, tls_fail={tls_fail_count}, tls_suspicious={tls_suspicious_count}, server_valid={server_response_valid})"
                )
                correlation_flags.append("ambiguous_server_response")
                correlation_flags.append("network_corrupted_server_response")
                if has_code_30003 and (tls_fail_count > 0 or tls_suspicion_points >= 2):
                    correlation_flags.append("server_response_untrusted")
                secondary.append(
                    "Terminal server signal detected, but transport path is degraded (DNS/TLS/timeout). "
                    "Server override was not forced."
                )
            else:
                terminal_override_applied = True
                if has_code_30003:
                    correlation_flags.append("hard_server_truth")
                if (
                    has_code_30003
                    and any(agg.count >= 2 for agg in parsed.xiaomi_json_aggregates)
                    and not network_signal_present
                ):
                    correlation_flags.append("likely_real_maintenance")
        if parsed.bind_success_detected:
            correlation_flags.append("bind_success_detected")
            secondary.append("Detected bind success pattern(s) in logs (possible server recovery window).")

        labels = [
            "bind_failure_network",
            "bind_failure_server",
            "bind_failure_account_state",
            "unlock_authorization_required",
        ]
        # Internal label (legacy) for score/evidence routing.
        if terminal_target is not None and (terminal_target != "bind_failure_server" or terminal_override_applied):
            internal_best_label = terminal_target
            terminal_override_applied = True
        else:
            internal_best_label = max(labels, key=lambda k: scores[k])
        # Authorization/business-policy should not be overshadowed by generic network noise.
        if (
            scores["unlock_authorization_required"] >= 10
            and (terminal_target in {None, "unlock_authorization_required"})
            and not (terminal_target == "bind_failure_server" and terminal_override_applied and has_code_30003 and server_response_valid)
        ):
            internal_best_label = "unlock_authorization_required"
        best_score = scores[internal_best_label]
        other_scores = [scores[label] for label in labels if label != internal_best_label]
        second_score = max(other_scores) if other_scores else 0

        confidence_floor = 0.0
        if terminal_target is not None and internal_best_label == terminal_target and (
            terminal_target != "bind_failure_server" or terminal_override_applied
        ):
            confidence_floor = 0.80
        hard_server_truth = (
            terminal_target == "bind_failure_server"
            and terminal_override_applied
            and has_code_30003
            and server_response_valid
        )
        if hard_server_truth:
            confidence_floor = max(confidence_floor, 0.85)

        confidence_k = 10
        if best_score <= 0:
            internal_best_label = "bind_failure_account_state"
            best_score = 1
            second_score = 0
            confidence = 0.05
            evidence[internal_best_label].append("Low-signal fallback: no decisive bind/network/server/auth indicators.")
            score_notes.append((internal_best_label, 1, "fallback due to insufficient evidence"))
        else:
            base_confidence = (best_score - second_score) / (best_score + confidence_k)
            confidence = round(max(confidence_floor, clamp(base_confidence, 0.05, 0.99)), 2)
            if conflict and not hard_server_truth:
                confidence = round(clamp(confidence * 0.78, 0.05, 0.99), 2)
        repeat_bonus = min(0.12, (recent_server_events + recent_timeout_events + recent_transport_events) * 0.01)
        if repeated_30003_count >= 2:
            repeat_bonus = max(repeat_bonus, min(0.15, repeated_30003_count * 0.03))
        if repeat_bonus > 0:
            confidence = round(clamp(confidence + repeat_bonus, 0.05, 0.99), 2)
        if has_code_30003 and not server_response_valid:
            confidence = round(clamp(confidence * 0.82, 0.05, 0.99), 2)
            secondary.append("False-positive guard: 30003 observed with degraded transport path; server confidence downgraded.")

        if conflict:
            if hard_server_truth and network_signal_present:
                conflict_type = "network_noise"
            else:
                conflict_type = "real_conflict"
        else:
            conflict_type = "none"

        total_raw_lines = capture.total_lines + capture.noise_filtered_count
        noise_ratio = (capture.noise_filtered_count / total_raw_lines) if total_raw_lines > 0 else 0.0
        if noise_ratio > 0.45:
            penalty = min(0.18, noise_ratio * abs(signal_weights["noise_penalty"]) * 0.35)
            confidence = round(clamp(confidence - penalty, 0.05, 0.99), 2)
            secondary.append(f"Noise penalty applied ({int(noise_ratio * 100)}% noisy lines in capture).")
        if conflict_type == "real_conflict" or noise_ratio >= 0.85:
            signal_quality = "unreliable"
        elif conflict_type == "network_noise" or noise_ratio >= 0.35 or network_signal_present:
            signal_quality = "noisy"
        else:
            signal_quality = "clean"

        no_xiaomi_json = len(parsed.xiaomi_json_aggregates) == 0
        timeout_detected = timeout_hits_total > 0
        timeout_with_xiaomi_context = ctx_timeout_hits > 0
        transport_checks_healthy = bool(net_health["healthy"])
        silent_server_degraded = (
            timeout_detected
            and timeout_with_xiaomi_context
            and no_xiaomi_json
            and transport_checks_healthy
            and scores["unlock_authorization_required"] == 0
        )
        possible_server_rate_limit = (
            timeout_detected
            and no_xiaomi_json
            and transport_checks_healthy
            and scores["unlock_authorization_required"] == 0
            and not has_code_30003
        )
        normal_operation = (
            parsed.bind_success_detected
            and scores["bind_failure_network"] == 0
            and scores["bind_failure_server"] == 0
            and scores["unlock_authorization_required"] == 0
            and scores["bind_failure_account_state"] == 0
        )

        # Public labels requested by user.
        def to_public_label(internal_label: str) -> str:
            if normal_operation:
                return "NORMAL_OPERATION"
            if possible_server_rate_limit:
                return "POSSIBLE_SERVER_RATE_LIMIT"
            if silent_server_degraded:
                return "SERVER_DEGRADED_NO_RESPONSE"
            if internal_label == "bind_failure_network":
                return "NETWORK_DISTORTION"
            if internal_label == "unlock_authorization_required":
                return "UNLOCK_AUTHORIZATION_REQUIRED"
            if internal_label == "bind_failure_account_state":
                return "AMBIGUOUS"
            # internal bind_failure_server
            if terminal_target == "bind_failure_server" and terminal_override_applied and server_response_valid:
                return "REAL_SERVER_MAINTENANCE"
            if conflict or (has_code_30003 and (tls_fail_count > 0 or tls_suspicion_points >= 2)):
                return "NETWORK_DISTORTION"
            return "SERVER_LIMITATION"

        public_label = to_public_label(internal_best_label)
        if public_label == "NORMAL_OPERATION":
            layer = "business_bind"
        elif public_label == "UNLOCK_AUTHORIZATION_REQUIRED":
            layer = "business_unlock"
        elif has_code_30003 or server_signal_present:
            layer = "server"
        elif public_label == "POSSIBLE_SERVER_RATE_LIMIT":
            layer = "business_bind"
        elif public_label == "SERVER_DEGRADED_NO_RESPONSE":
            layer = "server"
        elif timeout_detected and dns_fail_count == 0 and tls_fail_count == 0:
            layer = "server"
        elif public_label == "NETWORK_DISTORTION":
            layer = "network" if (dns_fail_count > 0 or tls_fail_count > 0) else "transport"
        elif public_label in {"REAL_SERVER_MAINTENANCE", "SERVER_LIMITATION"}:
            layer = "server"
        else:
            layer = "transport"
        if hard_server_truth and repeated_30003_count >= 2:
            server_trust_level = "absolute"
        elif hard_server_truth or (terminal_target == "bind_failure_server" and server_response_valid):
            server_trust_level = "strong"
        elif server_signal_present and net_health["ok_ratio"] >= 0.60:
            server_trust_level = "inferred"
        else:
            server_trust_level = "soft"
        if hard_server_truth and server_response_valid:
            confidence = max(confidence, 0.85)

        meaning_map = {
            "REAL_SERVER_MAINTENANCE": "Server-side maintenance/degradation is the most reliable explanation for bind failure.",
            "SERVER_DEGRADED_NO_RESPONSE": "Server appears degraded/unresponsive: timeout detected while DNS/TLS path is healthy and no Xiaomi JSON response was captured.",
            "POSSIBLE_SERVER_RATE_LIMIT": "Timeout occurred with healthy DNS/TLS and no Xiaomi JSON response; server-side rate-limit/degraded behavior is likely.",
            "NETWORK_DISTORTION": "Network/TLS integrity issues likely distort or block reliable bind responses.",
            "UNLOCK_AUTHORIZATION_REQUIRED": "Xiaomi unlock authorization/eligibility policy blocks progress (Mi Community/permission stage).",
            "SERVER_LIMITATION": "Server-side limitation/authorization policy appears to block progress.",
            "NORMAL_OPERATION": "Bind flow appears healthy in this capture (success detected, no major error signals).",
            "AMBIGUOUS": "Signals are mixed/weak; account/device-state or mixed factors are possible.",
        }

        if internal_best_label.startswith("bind_failure_") and scores["unlock_authorization_required"] > 0:
            secondary.append("Unlock authorization signals were detected, but they are reported separately from bind-stage root cause.")
        if internal_best_label == "unlock_authorization_required" and any(scores[k] > 0 for k in ("bind_failure_network", "bind_failure_server", "bind_failure_account_state")):
            secondary.append("Bind-stage signals also exist; unlock authorization selected as stronger root cause in this capture.")
        human_why: list[str] = []
        if has_code_30003:
            human_why.append("Xiaomi explicitly returned maintenance code 30003.")
        if server_response_valid:
            human_why.append("Network path to Xiaomi domains is valid (DNS/TLS/latency checks passed).")
        if repeated_30003_count >= 2:
            human_why.append(f"Maintenance response repeated {repeated_30003_count} times, reducing random-noise likelihood.")
        if network_state == "degraded":
            human_why.append("Network shows degradation (timeouts/jitter/noise), but not full transport failure.")
        elif network_state == "failing":
            human_why.append("Network transport failures detected (DNS/TLS), so server replies may be unreliable.")
        if not human_why:
            human_why.append("No single dominant explanation; diagnosis is based on mixed weak signals.")
        if silent_server_degraded:
            human_why.append("Timeout observed with healthy DNS/TLS and no Xiaomi JSON: likely server-side degraded response path.")
        if possible_server_rate_limit:
            human_why.append("Timeout with healthy DNS/TLS and missing Xiaomi JSON suggests possible server rate-limit/degraded bind backend.")
        if normal_operation:
            human_why.append("Bind success detected without competing server/network/account error signals.")
        server_causal = bool(hard_server_truth or (server_signal_present and terminal_override_applied))
        authorization_causal = bool(
            (internal_best_label == "unlock_authorization_required" or public_label == "UNLOCK_AUTHORIZATION_REQUIRED")
            and not hard_server_truth
        )
        network_causal = bool(
            network_state == "failing"
            and not server_causal
            and not authorization_causal
        )
        device_causal = bool(scores["bind_failure_account_state"] > 0 and not server_causal and not network_causal and not authorization_causal)
        if server_causal:
            root_cause = "server"
        elif authorization_causal:
            root_cause = "authorization"
        elif network_causal:
            root_cause = "network"
        elif device_causal:
            root_cause = "device"
        else:
            root_cause = "unknown"
        truth_layer = {
            "server": root_cause == "server",
            "network": root_cause == "network",
            "device": root_cause == "device",
            "authorization": root_cause == "authorization",
        }
        side_effects: list[str] = []
        if network_state in {"degraded", "failing"} and root_cause != "network":
            side_effects.append("network_noise")
        if public_label == "NETWORK_DISTORTION" and "network_instability" not in side_effects:
            side_effects.append("network_instability")
        if scores["bind_failure_account_state"] > 0 and root_cause != "device":
            side_effects.append("device_state")
        if authorization_signal_present and root_cause != "authorization":
            side_effects.append("authorization_policy")
        latency_values = [x.latency_ms for x in domain_checks if x.latency_ms is not None]
        avg_latency = int(sum(latency_values) / len(latency_values)) if latency_values else None
        latency_level = "unknown"
        if avg_latency is not None:
            if avg_latency >= 350:
                latency_level = "high"
            elif avg_latency >= 150:
                latency_level = "medium"
            else:
                latency_level = "low"
        network_profile = {
            "latency": net_health["latency_state"] if net_health["latency_state"] != "unknown" else latency_level,
            "jitter": jitter_state,
            "packet_loss": "unknown",
            "tls": "ok" if net_health["tls_ok_ratio"] >= 0.60 else "failing",
            "timeout": "present" if timeout_hits_total > 0 else "none",
            "ok_ratio": f"{int(net_health['ok_ratio'] * 100)}%",
            "healthy": "yes" if net_health["healthy"] else "no",
            "layer_priority": str(LAYER_PRIORITY.get(layer, 0)),
        }
        causal_graph: list[str] = []
        if root_cause == "server":
            causal_graph.append("server -> bind_failure")
            if "network_noise" in side_effects:
                causal_graph.append("network_noise -> latency/timeout")
        elif root_cause == "authorization":
            causal_graph.append("authorization_policy -> unlock_blocked")
            causal_graph.append("authorization_block -> bind/unlock progression stopped")
        elif root_cause == "network":
            causal_graph.append("network -> bind_failure")
        elif root_cause == "device":
            causal_graph.append("device_state -> bind_failure")
        else:
            causal_graph.append("insufficient_evidence -> ambiguous_bind_failure")
        action, action_message, retry_after_sec = self._suggest_action(
            root_cause=root_cause,
            public_label=public_label,
            internal_label=internal_best_label,
            network_state=network_state,
            global_status_hint=None,
        )
        if public_label == "REAL_SERVER_MAINTENANCE":
            action = "WAIT"
            action_message = "Xiaomi servers under maintenance. Retry in 30-60 min."
            retry_after_sec = random.randint(1200, 3600)
        elif public_label == "SERVER_DEGRADED_NO_RESPONSE":
            action = "RETRY_LATER"
            action_message = "Server not responding properly. Try again soon."
            retry_after_sec = random.randint(60, 300)
        elif layer == "network":
            action = "FIX_NETWORK"
            action_message = "Network unstable. Try another Wi-Fi or mobile network."
            retry_after_sec = None
        elif public_label == "NORMAL_OPERATION":
            action = "SUCCESS"
            action_message = "No immediate bind fault detected in this run."
            retry_after_sec = None
        if conflict_type == "network_noise" and hard_server_truth:
            conflict_reason = "network noise present, but server signal is authoritative"
        conflict_resolution = "server_wins" if (conflict_type == "network_noise" and hard_server_truth) else "none"
        if server_causal and network_state in {"degraded", "failing"}:
            network_state = "secondary"
        if confidence > 0.85:
            confidence_level = "CONFIRMED"
        elif confidence > 0.65:
            confidence_level = "LIKELY"
        else:
            confidence_level = "UNCERTAIN"

        score_notes_sorted = sorted(score_notes, key=lambda x: x[1], reverse=True)
        confidence_header = (
            f"best_score({internal_best_label})={best_score}, second_score={second_score}, "
            f"K={confidence_k}, P0_floor={confidence_floor:.2f}, net_ok_ratio={net_health['ok_ratio']:.2f}"
        )
        confidence_lines = [confidence_header]
        confidence_lines.extend(
            f"{label}: +{pts} ({note})"
            for label, pts, note in score_notes_sorted[:3]
        )
        if not confidence_lines:
            confidence_lines = ["No strong scoring factors were found."]

        filtered_noise = [f"{capture.noise_filtered_count} lines filtered as noise"]
        for example in capture.noise_examples[:3]:
            filtered_noise.append(f"filtered: {example[:160]}")
        if terminal_override_reason:
            if terminal_override_applied:
                confidence_lines.append(f"terminal_override: {terminal_override_reason}")
            else:
                confidence_lines.append(f"terminal_event_detected_no_override: {terminal_override_reason}")
        if hard_server_truth:
            confidence_lines.append(
                "hard_truth: code=30003 with valid DNS/TLS path; server maintenance is treated as primary truth"
            )
        if conflict and conflict_reason:
            confidence_lines.append(f"conflict: {conflict_reason}")
        confidence_lines.append(f"network_state={network_state}, server_trust_level={server_trust_level}")
        confidence_lines.append(
            f"signal_weights: server={signal_weights['server']:.2f}, business={signal_weights['business']:.2f}, "
            f"transport={signal_weights['transport']:.2f}, network={signal_weights['network']:.2f}"
        )

        secondary_label = None
        ranked_other = sorted(
            ((scores[label], label) for label in labels if label != internal_best_label),
            reverse=True,
        )
        if ranked_other and ranked_other[0][0] > 0:
            secondary_label = to_public_label(ranked_other[0][1])

        return Classification(
            label=public_label,
            confidence=confidence,
            root_evidence=self._dedup_keep_order(evidence[internal_best_label], limit=3),
            confidence_explanation=self._dedup_keep_order(confidence_lines, limit=8),
            secondary=self._dedup_keep_order(secondary, limit=8),
            secondary_label=secondary_label,
            internal_label=internal_best_label,
            conflict=conflict,
            conflict_reason=conflict_reason,
            correlation_flags=self._dedup_keep_order(correlation_flags, limit=6),
            meaning=meaning_map[public_label],
            filtered_noise=filtered_noise,
            scores=scores,
            best_score=best_score,
            second_score=second_score,
            confidence_floor=confidence_floor,
            confidence_k=confidence_k,
            terminal_override_applied=terminal_override_applied,
            terminal_override_reason=terminal_override_reason,
            conflict_type=conflict_type,
            signal_quality=signal_quality,
            server_authority=hard_server_truth,
            layer=layer,
            noise_ratio=round(noise_ratio, 3),
            network_state=network_state,
            server_trust_level=server_trust_level,
            human_why=self._dedup_keep_order(human_why, limit=4),
            truth_layer=truth_layer,
            root_cause=root_cause,
            side_effects=self._dedup_keep_order(side_effects, limit=4),
            network_profile=network_profile,
            causal_graph=self._dedup_keep_order(causal_graph, limit=4),
            action=action,
            action_message=action_message,
            confidence_level=confidence_level,
            conflict_resolution=conflict_resolution,
            retry_after_sec=retry_after_sec,
        )


# =========================
# reporter
# =========================


def _fmt_yes_no(v: bool) -> str:
    return "yes" if v else "no"


def _collapse_noise_lines(lines: list[str]) -> list[str]:
    collapsed: list[str] = []
    hidden = 0
    for line in lines:
        if is_noise_line(line):
            hidden += 1
            continue
        if hidden > 0:
            collapsed.append(f"... <{hidden} noise lines hidden> ...")
            hidden = 0
        collapsed.append(redact_sensitive_text(line))
    if hidden > 0:
        collapsed.append(f"... <{hidden} noise lines hidden> ...")
    return collapsed


def _status_style(status: str) -> str:
    if status in {
        "XIAOMI_DOWN",
        "CONFIRMED_SERVER_MAINTENANCE",
        "LIKELY_SERVER_MAINTENANCE",
        "STABLE_SERVER_FAILURE",
        "NOT_ELIGIBLE_FOR_UNLOCK",
    }:
        return "bold red"
    if status in {
        "NETWORK_ENVIRONMENT_UNSTABLE",
        "INTERMITTENT_NETWORK",
        "INCONCLUSIVE",
        "SERVER_DEGRADED_NO_RESPONSE",
        "POSSIBLE_SERVER_RATE_LIMIT",
    }:
        return "yellow"
    if status in {"STATE_TRANSITION_MAINTENANCE_TO_OK", "BIND_OK_OBSERVED", "NORMAL_OPERATION", "NORMAL"}:
        return "bold green"
    return "white"


def _confidence_style(value: float) -> str:
    if value >= 0.85:
        return "bold green"
    if value >= 0.60:
        return "bold yellow"
    return "bold red"


def render_minimal_line(report: DiagnosisReport, color_enabled: bool = True) -> bool:
    status = (report.global_status or {}).get("status", "INCONCLUSIVE")
    retry_hint = (report.global_status or {}).get("retry_hint")
    diag_seg = ansi(f"🔥 {report.classification.label}", color_status(report.classification.label), color_enabled)
    if not color_enabled:
        tail = f" | {retry_hint}" if retry_hint else ""
        retry_seg = f" | next_retry~{report.classification.retry_after_sec}s" if report.classification.retry_after_sec is not None else ""
        print(
            f"{status} | {diag_seg} | {report.classification.network_state} | confidence={report.classification.confidence:.2f} "
            f"({report.classification.confidence_level}) | action={report.classification.action}{retry_seg}{tail}"
        )
        return True
    try:
        from rich.console import Console
    except Exception:
        tail = f" | {retry_hint}" if retry_hint else ""
        retry_seg = f" | next_retry~{report.classification.retry_after_sec}s" if report.classification.retry_after_sec is not None else ""
        print(
            f"{status} | {diag_seg} | {report.classification.network_state} | confidence={report.classification.confidence:.2f} "
            f"({report.classification.confidence_level}) | action={report.classification.action}{retry_seg}{tail}"
        )
        return False
    console = Console(force_terminal=True, color_system="auto")
    icon = "🔥" if status in {"XIAOMI_DOWN", "CONFIRMED_SERVER_MAINTENANCE", "LIKELY_SERVER_MAINTENANCE", "STABLE_SERVER_FAILURE"} else "✓"
    status_style = _status_style(status)
    conf_style = _confidence_style(report.classification.confidence)
    diag_style = (
        "bold red"
        if "SERVER" in report.classification.label
        else "bold yellow"
        if "NETWORK" in report.classification.label
        else "bold green"
        if "SUCCESS" in report.classification.label or report.classification.label == "NORMAL_OPERATION"
        else "bold white"
    )
    tail = f" [white]|[/white] [yellow]{retry_hint}[/yellow]" if retry_hint else ""
    retry_seg = (
        f" [white]|[/white] [yellow]next_retry~{report.classification.retry_after_sec}s[/yellow]"
        if report.classification.retry_after_sec is not None
        else ""
    )
    console.print(
        f"[{status_style}]{icon} {status}[/{status_style}] [white]|[/white] "
        f"[{diag_style}]🔥 {report.classification.label}[/{diag_style}] [white]|[/white] "
        f"[yellow]{report.classification.network_state}[/yellow] [white]|[/white] "
        f"[{conf_style}]confidence={report.classification.confidence:.2f}[/{conf_style}] "
        f"({report.classification.confidence_level}) [white]|[/white] "
        f"[bold cyan]{report.classification.action}[/bold cyan]{retry_seg}{tail}"
    )
    return True


def render_initial_bind_panel(tool_version: str, serial: str, created_at_utc: str, color_enabled: bool = True) -> bool:
    if not color_enabled:
        print(f"Bind Diagnostics | Xiaomi Unlock Assistant v{tool_version} | INCONCLUSIVE | serial={serial} | time={created_at_utc}")
        return True
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
    except Exception:
        print(f"Bind Diagnostics | Xiaomi Unlock Assistant v{tool_version} | INCONCLUSIVE | serial={serial} | time={created_at_utc}")
        return False
    console = Console(force_terminal=True, color_system="auto")
    title = Text("📱 Bind Diagnostics", style="bold cyan")
    content = (
        f"[bold magenta]Xiaomi Unlock Assistant v{tool_version}[/bold magenta]\n"
        f"[bold red]🔥 INCONCLUSIVE[/bold red]\n"
        f"[dim]Serial:[/dim] [cyan]{serial}[/cyan]\n"
        f"[dim]Time (UTC):[/dim] [yellow]{created_at_utc}[/yellow]"
    )
    console.print(
        Panel(
            content,
            title=title,
            border_style="bright_blue",
            padding=(1, 2),
        )
    )
    return True


def render_human_report_rich(report: DiagnosisReport, color_enabled: bool = True) -> bool:
    if not color_enabled:
        return False
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except Exception:
        return False

    console = Console(force_terminal=True, color_system="auto")
    cls = report.classification
    global_status = (report.global_status or {}).get("status", "INCONCLUSIVE")
    icons = {
        "server": "🖥",
        "network": "🌐",
        "warning": "⚠",
        "error": "🔥",
        "ok": "✓",
        "brain": "🧠",
    }
    diag_style = (
        "bold red"
        if cls.label in {"REAL_SERVER_MAINTENANCE", "REAL_RATE_LIMIT", "SERVER_DEGRADATION", "SERVER_SILENT_DROP", "UNLOCK_AUTHORIZATION_REQUIRED"}
        else "yellow"
        if cls.label in {"NETWORK_DISTORTION", "AMBIGUOUS", "SERVER_DEGRADED_NO_RESPONSE", "POSSIBLE_SERVER_RATE_LIMIT"}
        else "bold green"
    )
    global_style = _status_style(global_status)
    conf_style = _confidence_style(cls.confidence)
    border_style = "red" if "DOWN" in global_status else "yellow" if "UNSTABLE" in global_status else "bright_blue"

    title = Text("📱 Bind Diagnostics", style="bold cyan")
    header_content = (
        f"[bold magenta]Xiaomi Unlock Assistant v{report.tool_version}[/bold magenta]\n"
        f"[{global_style}]{icons['error']} {global_status}[/{global_style}]\n"
        f"[{diag_style}]{icons['error']} {cls.label}[/{diag_style}]\n"
        f"[dim]Serial:[/dim] [cyan]{report.serial}[/cyan]\n"
        f"[dim]Time (UTC):[/dim] [yellow]{report.created_at_utc}[/yellow]"
    )
    console.print(
        Panel(
            header_content,
            title=title,
            border_style=border_style,
            padding=(1, 2),
        )
    )

    summary = Table(show_header=False, box=None, pad_edge=False)
    summary.add_column(style="bold", width=20)
    summary.add_column()
    summary.add_row("Diagnosis", f"[{diag_style}]{cls.label}[/{diag_style}]")
    summary.add_row("Global status", f"[{global_style}]{icons['error']} {global_status}[/{global_style}]")
    summary.add_row("Network state", f"[yellow]{icons['network']} {cls.network_state}[/yellow]")
    summary.add_row("Server trust", f"[cyan]{icons['server']} {cls.server_trust_level}[/cyan]")
    summary.add_row("Confidence", f"[{conf_style}]{icons['brain']} {cls.confidence:.2f}[/{conf_style}]")
    summary.add_row("Confidence lvl", cls.confidence_level)
    summary.add_row("Signal quality", cls.signal_quality)
    summary.add_row("Action", f"[bold cyan]{cls.action}[/bold cyan]")
    if cls.retry_after_sec is not None:
        summary.add_row("Next retry", f"[yellow]~{cls.retry_after_sec} sec[/yellow]")
    if report.global_status and report.global_status.get("retry_hint"):
        summary.add_row("Retry hint", f"[yellow]{icons['warning']} {report.global_status.get('retry_hint')}[/yellow]")
    console.print(Panel(summary, title="Summary", border_style="magenta"))

    if cls.human_why:
        console.rule("[bold green]Why[/bold green]")
        why_table = Table(show_header=False, box=None, pad_edge=False)
        why_table.add_column()
        for reason in cls.human_why[:4]:
            why_table.add_row(f"- {reason}")
        console.print(Panel(why_table, title="Why", border_style="green"))
    console.print(Panel(f"[bold cyan]{cls.action}[/bold cyan]\n{cls.action_message}", title="Action", border_style="cyan"))

    console.rule("[bold red]Root Evidence[/bold red]")
    root_table = Table(show_header=False, box=None, pad_edge=False)
    root_table.add_column()
    for item in cls.root_evidence[:3] or ["No high-signal evidence lines were captured."]:
        root_table.add_row(f"- {item}")
    console.print(Panel(root_table, title="Root Evidence", border_style="red"))
    return True


def render_human_report(report: DiagnosisReport) -> str:
    lines: list[str] = []

    lines.append(f"Xiaomi Unlock Assistant v{report.tool_version}")
    lines.append(f"Time (UTC): {report.created_at_utc}")
    lines.append(f"Serial: {report.serial}")
    lines.append("")

    lines.append(f"🔥 {report.classification.label}")
    lines.append(f"Diagnosis: {report.classification.label} (confidence={report.classification.confidence:.2f})")
    lines.append(f"PRIMARY: {report.classification.label}")
    lines.append(f"SECONDARY: {report.classification.secondary_label or '<none>'}")
    lines.append(f"CONFLICT: {'yes' if report.classification.conflict else 'no'}")
    lines.append(f"CONFLICT_TYPE: {report.classification.conflict_type}")
    lines.append(f"CONFLICT_RESOLUTION: {report.classification.conflict_resolution}")
    lines.append(f"SERVER_AUTHORITY: {'TRUE' if report.classification.server_authority else 'FALSE'}")
    lines.append(f"SERVER_TRUST_LEVEL: {report.classification.server_trust_level}")
    lines.append(f"NETWORK_STATE: {report.classification.network_state}")
    lines.append(f"ROOT_CAUSE: {report.classification.root_cause}")
    lines.append(f"SIDE_EFFECTS: {', '.join(report.classification.side_effects) if report.classification.side_effects else '<none>'}")
    lines.append(f"TRUTH_LAYER: {json.dumps(report.classification.truth_layer, ensure_ascii=False)}")
    lines.append(f"CAUSAL_GRAPH: {'; '.join(report.classification.causal_graph)}")
    lines.append(f"ACTION: {report.classification.action}")
    lines.append(f"ACTION_MESSAGE: {report.classification.action_message}")
    lines.append(f"SIGNAL_QUALITY: {report.classification.signal_quality}")
    lines.append(f"CONFIDENCE_LEVEL: {report.classification.confidence_level}")
    if report.classification.retry_after_sec is not None:
        lines.append(f"NEXT_RETRY_SEC: ~{report.classification.retry_after_sec}")
    lines.append(f"LAYER: {report.classification.layer}")
    lines.append(f"NOISE_LEVEL: {int(report.classification.noise_ratio * 100)}%")
    if report.classification.conflict_reason:
        lines.append(f"CONFLICT_REASON: {report.classification.conflict_reason}")
    if report.classification.correlation_flags:
        lines.append(f"CORRELATION_FLAGS: {', '.join(report.classification.correlation_flags)}")
    lines.append("")

    if report.global_status is not None:
        lines.append(f"GLOBAL_STATUS: {report.global_status.get('status')}")
        lines.append(
            f"OBSERVED_RUNS: {report.global_status.get('confirmed_runs')}/{report.global_status.get('observed_runs')}"
        )
        lines.append(f"DURATION: {report.global_status.get('duration_minutes')} minutes")
        lines.append(f"HISTORY_WINDOW: {report.global_status.get('window_minutes')} minutes")
        lines.append(f"STATUS_CONFIDENCE: {report.global_status.get('status_confidence')}")
        if report.global_status.get("weighted_observed_runs") is not None:
            lines.append(
                f"WEIGHTED_OBSERVED: {report.global_status.get('weighted_confirmed_runs'):.2f}/{report.global_status.get('weighted_observed_runs'):.2f}"
            )
        if report.global_status.get("freshness_minutes") is not None:
            lines.append(f"LAST_SEEN_MINUTES: {report.global_status.get('freshness_minutes')}")
        if report.global_status.get("decay_applied"):
            lines.append(f"CONFIDENCE_DECAY_APPLIED: {report.global_status.get('decay_applied')}")
        if report.global_status.get("retry_hint"):
            lines.append(f"RETRY_HINT: {report.global_status.get('retry_hint')}")
        trend_last5 = report.global_status.get("trend_last5") or []
        if trend_last5:
            lines.append(f"TREND: last 5 runs: {', '.join(trend_last5)}")
        trend_stability = report.global_status.get("trend_stability")
        if trend_stability:
            lines.append(f"TREND_STABILITY: {trend_stability}")
        if report.global_status.get("state_transition"):
            lines.append(f"STATE TRANSITION: {report.global_status.get('state_transition')}")
        lines.append("")

    lines.append("ROOT EVIDENCE:")
    if report.classification.root_evidence:
        for reason in report.classification.root_evidence:
            lines.append(f"- {reason}")
    else:
        lines.append("- No high-signal evidence lines were captured.")
    lines.append("")

    lines.append("WHY:")
    for reason in report.classification.human_why:
        lines.append(f"- {reason}")
    lines.append("")

    lines.append("NETWORK_PROFILE:")
    for k, v in report.classification.network_profile.items():
        lines.append(f"- {k}: {v}")
    lines.append("")

    lines.append("Confidence explanation:")
    for item in report.classification.confidence_explanation:
        lines.append(f"- {item}")
    if report.classification.terminal_override_applied:
        lines.append("- terminal_override_applied: yes")
    for item in report.classification.filtered_noise:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("Secondary:")
    if report.classification.secondary:
        for item in report.classification.secondary:
            lines.append(f"- {item}")
    else:
        lines.append("- No secondary indicators")
    lines.append("")

    lines.append("Meaning:")
    lines.append(f"- {report.classification.meaning}")
    if report.classification.internal_label.startswith("bind_failure_"):
        lines.append("- This diagnosis is about bind account stage and is not a direct unlock quota decision.")
    elif report.classification.internal_label == "unlock_authorization_required":
        lines.append("- This is unlock authorization/quota stage, separate from bind transport diagnostics.")
    lines.append("")

    lines.append("Trigger:")
    if report.capture.trigger is None:
        lines.append("- No trigger event detected in capture window")
    else:
        lines.append(
            f"- [{report.capture.trigger.pattern_group} P{report.capture.trigger.priority} score={report.capture.trigger.score}] "
            f"{redact_sensitive_text(report.capture.trigger.line)}"
        )
    lines.append("")

    if report.event_flow:
        lines.append("FLOW:")
        lines.append(f"- {' -> '.join(report.event_flow)}")
        lines.append("")

    lines.append("Context before (up to 20 lines):")
    before = _collapse_noise_lines(report.capture.context_before[-20:])
    if before:
        for line in before:
            lines.append(f"  {line}")
    else:
        lines.append("  <empty>")

    lines.append("")
    lines.append("Context after (up to 20 lines):")
    after = _collapse_noise_lines(report.capture.context_after[:20])
    if after:
        for line in after:
            lines.append(f"  {line}")
    else:
        lines.append("  <empty>")
    lines.append("")

    lines.append("Device snapshot:")
    d = report.device_snapshot
    lines.append(f"- serial: {d.serial}")
    lines.append(f"- model: {d.model}")
    lines.append(f"- android: {d.android_version}")
    lines.append(f"- miui: {d.miui_version}")
    lines.append(f"- hyperos: {d.hyperos_version}")
    lines.append(f"- region: {d.region}")
    lines.append(f"- sim_state: {d.sim_state}")
    sim_tokens = (d.sim_state or "").upper()
    lines.append(f"- sim_summary: {'active_slot_present' if ('READY' in sim_tokens or 'LOADED' in sim_tokens) else 'no_active_slot_detected'}")
    lines.append(f"- operator: {d.operator_alpha} ({d.operator_numeric})")
    lines.append(f"- auto_time: {d.auto_time}, auto_time_zone: {d.auto_time_zone}")
    lines.append(f"- time_skew_s (device-host): {d.time_skew_s}")
    lines.append(f"- dns: {json.dumps(d.dns, ensure_ascii=False)}")
    lines.append("")

    lines.append("Host network checks (DNS/TLS):")
    lines.append(f"- latency_jitter: {classify_latency_jitter(report.host_domain_checks)}")
    for check in report.host_domain_checks:
        lines.append(
            f"- {check.domain}: dns_ok={_fmt_yes_no(check.dns_ok)}, tls_ok={_fmt_yes_no(check.tls_ok)}, "
            f"latency_ms={check.latency_ms}, dns_error={check.dns_error}, tls_error={check.tls_error}, "
            f"tls_failure_type={check.tls_failure_type}"
        )
    lines.append("")

    if report.phone_network_checks:
        lines.append("Phone optional network checks (adb shell):")
        for c in report.phone_network_checks[:12]:
            compact = c.output.replace("\n", " | ")
            lines.append(f"- {c.command}: {compact[:220]}")
    lines.append("")

    if report.parsed.xiaomi_json_aggregates:
        lines.append("Xiaomi response aggregation:")
        for agg in report.parsed.xiaomi_json_aggregates[:6]:
            lines.append(
                f"- code={agg.code}, count={agg.count}, first_seen={agg.first_seen}, last_seen={agg.last_seen}, desc={agg.desc[:140]}"
            )
        lines.append("")

    if report.parsed.bind_success_detected:
        lines.append("Bind success detection:")
        lines.append("- bind_success_detected: yes")
        for item in report.parsed.success_evidence[:5]:
            lines.append(f"- evidence: {item}")
        lines.append("")

    lines.append("Parsed evidence summary:")
    lines.append(f"- total_log_lines: {report.capture.total_lines}")
    lines.append(f"- urls_redacted: {', '.join(report.parsed.urls_redacted[:12]) if report.parsed.urls_redacted else '<none>'}")
    lines.append(f"- domains_trusted: {', '.join(report.parsed.domains_trusted[:20]) if report.parsed.domains_trusted else '<none>'}")
    lines.append(f"- domains_rejected: {', '.join(report.parsed.domains_rejected[:10]) if report.parsed.domains_rejected else '<none>'}")
    lines.append(
        f"- http_statuses: {', '.join(str(x) for x in report.parsed.http_statuses[:30]) if report.parsed.http_statuses else '<none>'}"
    )
    lines.append(
        f"- non_http_status_hints: {len(report.parsed.non_http_status_hints)}"
    )
    lines.append(f"- exceptions: {', '.join(report.parsed.exceptions) if report.parsed.exceptions else '<none>'}")
    lines.append(f"- bind_success_detected: {_fmt_yes_no(report.parsed.bind_success_detected)}")
    if report.parsed.xiaomi_json_events:
        lines.append(f"- xiaomi_json_events: {len(report.parsed.xiaomi_json_events)}")

    return "\n".join(lines)


def save_report_files(
    report: DiagnosisReport,
    out_dir: Path,
    save_human: bool,
    save_json: bool,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []

    if save_json:
        json_path = out_dir / "diagnosis_report.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(report), f, ensure_ascii=False, indent=2)
        written.append(json_path)

    if save_human:
        txt_path = out_dir / "diagnosis_report.txt"
        with txt_path.open("w", encoding="utf-8") as f:
            f.write(render_human_report(report))
            f.write("\n")
        written.append(txt_path)

    return written


# =========================
# history + trend helpers
# =========================


def summarize_event_flow(events: list[EventRecord]) -> list[str]:
    group_map = {
        "dns_error": "dns_failure",
        "tls_ssl_error": "tls_failure",
        "timeout": "timeout",
        "http_error_p1": "http_error",
        "xiaomi_response_p0": "xiaomi_response",
        "xiaomi_specific_event": "xiaomi_stage_event",
    }
    flow: list[str] = []
    last = None
    for ev in events[:60]:
        step = group_map.get(ev.pattern_group, ev.pattern_group)
        if step == last:
            continue
        flow.append(step)
        last = step
        if len(flow) >= 12:
            break
    return flow


def classify_latency_jitter(checks: list[DomainCheck]) -> str:
    values = [x.latency_ms for x in checks if x.latency_ms is not None and x.dns_ok and x.tls_ok]
    if not values:
        return "unknown"
    if len(values) == 1:
        return "low"
    spread = max(values) - min(values)
    return "low" if spread <= 50 else "high"


def resolve_history_path(args: argparse.Namespace) -> Path:
    if getattr(args, "history_file", None):
        return Path(args.history_file)
    return Path.home() / ".xiaomi_unlock_assistant_history.jsonl"


def load_history_entries(path: Path) -> list[HistoryEntry]:
    if not path.exists():
        return []
    entries: list[HistoryEntry] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    entries.append(
                        HistoryEntry(
                            ts_utc=str(payload.get("ts_utc") or now_utc_iso()),
                            serial=str(payload.get("serial") or ""),
                            diagnosis=str(payload.get("diagnosis") or "AMBIGUOUS"),
                            confidence=float(payload.get("confidence") or 0.0),
                            cloud_code=payload.get("cloud_code"),
                            server_authority=bool(payload.get("server_authority")),
                            network_signal=bool(payload.get("network_signal")),
                            bind_success=bool(payload.get("bind_success")),
                            conflict=bool(payload.get("conflict")),
                            signal_quality=str(payload.get("signal_quality") or "noisy"),
                            timeout_signal=bool(payload.get("timeout_signal")),
                            network_ok_ratio=float(payload.get("network_ok_ratio") or 0.0),
                            latency_state=str(payload.get("latency_state") or "unknown"),
                            attempt_interval_sec=(
                                int(payload.get("attempt_interval_sec"))
                                if payload.get("attempt_interval_sec") is not None
                                else None
                            ),
                        )
                    )
                except Exception:
                    continue
    except Exception:
        return []
    return entries[-HISTORY_MAX_ENTRIES:]


def persist_history_entries(path: Path, entries: list[HistoryEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    trimmed = entries[-HISTORY_MAX_ENTRIES:]
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for item in trimmed:
            f.write(json.dumps(dataclasses.asdict(item), ensure_ascii=False) + "\n")
    tmp.replace(path)


def build_history_entry(
    serial: str,
    classification: Classification,
    parsed: ParsedEvidence,
    prev_entry: Optional[HistoryEntry] = None,
) -> HistoryEntry:
    code: Optional[str] = None
    if parsed.xiaomi_json_aggregates:
        code = parsed.xiaomi_json_aggregates[0].code
    now_ts = now_utc_iso()
    prev_ts = parse_iso_utc(prev_entry.ts_utc) if prev_entry is not None else None
    cur_ts = parse_iso_utc(now_ts)
    interval_sec: Optional[int] = None
    if prev_ts is not None and cur_ts is not None:
        interval_sec = max(0, int((cur_ts - prev_ts).total_seconds()))
    timeout_signal = classification.network_profile.get("timeout") == "present"
    ok_ratio = _parse_ratio_percent(classification.network_profile.get("ok_ratio"))
    latency_state = str(classification.network_profile.get("latency") or "unknown")
    return HistoryEntry(
        ts_utc=now_ts,
        serial=serial,
        diagnosis=classification.label,
        confidence=classification.confidence,
        cloud_code=code,
        server_authority=classification.server_authority,
        network_signal=classification.scores.get("bind_failure_network", 0) > 0,
        bind_success=parsed.bind_success_detected,
        conflict=classification.conflict,
        signal_quality=classification.signal_quality,
        timeout_signal=timeout_signal,
        network_ok_ratio=ok_ratio,
        latency_state=latency_state,
        attempt_interval_sec=interval_sec,
    )


def assess_global_trend(
    history: list[HistoryEntry],
    current: HistoryEntry,
    window_minutes: int,
) -> GlobalTrend:
    now_ts = parse_iso_utc(current.ts_utc) or dt.datetime.now(dt.timezone.utc)
    same_serial = [x for x in history if x.serial == current.serial]
    same_serial = sorted(same_serial, key=lambda x: parse_iso_utc(x.ts_utc) or now_ts)
    cutoff = now_ts - dt.timedelta(minutes=max(1, window_minutes))
    windowed = [x for x in same_serial if (parse_iso_utc(x.ts_utc) or now_ts) >= cutoff]
    if not windowed:
        windowed = [current]

    confirmed_server = [
        x for x in windowed
        if x.diagnosis == "REAL_SERVER_MAINTENANCE" and x.server_authority and x.cloud_code == "30003"
    ]
    observed_runs = len(windowed)
    confirmed_runs = len(confirmed_server)
    weighted_observed = 0.0
    weighted_confirmed = 0.0
    for x in windowed:
        ts = parse_iso_utc(x.ts_utc) or now_ts
        age_minutes = max(0.0, (now_ts - ts).total_seconds() / 60.0)
        w = math.exp(-age_minutes / 30.0)
        weighted_observed += w
        if x.diagnosis == "REAL_SERVER_MAINTENANCE" and x.server_authority and x.cloud_code == "30003":
            weighted_confirmed += w

    state_transition: Optional[str] = None
    prev_window = windowed[:-1]
    if current.bind_success and any(x.diagnosis == "REAL_SERVER_MAINTENANCE" for x in prev_window):
        state_transition = "MAINTENANCE -> OK"

    recent10 = same_serial[-10:] if same_serial else [current]
    recent5 = same_serial[-5:] if same_serial else [current]
    network_runs = [x for x in recent10 if x.diagnosis == "NETWORK_DISTORTION"]
    success_runs = [x for x in recent10 if x.bind_success or x.diagnosis == "NORMAL_OPERATION"]

    if state_transition == "MAINTENANCE -> OK":
        status = "STATE_TRANSITION_MAINTENANCE_TO_OK"
    elif current.diagnosis == "NORMAL_OPERATION":
        status = "NORMAL"
    elif current.diagnosis == "UNLOCK_AUTHORIZATION_REQUIRED":
        status = "NOT_ELIGIBLE_FOR_UNLOCK"
    elif confirmed_runs >= 3 or weighted_confirmed >= 2.2:
        status = "STABLE_SERVER_FAILURE"
    elif confirmed_runs >= 2 or weighted_confirmed >= 1.4:
        status = "CONFIRMED_SERVER_MAINTENANCE"
    elif current.diagnosis == "REAL_SERVER_MAINTENANCE" and current.server_authority:
        status = "LIKELY_SERVER_MAINTENANCE"
    elif len(network_runs) >= 3 and len(success_runs) >= 1:
        status = "INTERMITTENT_NETWORK"
    elif current.diagnosis == "NETWORK_DISTORTION":
        status = "NETWORK_ENVIRONMENT_UNSTABLE"
    elif current.bind_success:
        status = "NORMAL"
    else:
        status = "INCONCLUSIVE"

    times = [parse_iso_utc(x.ts_utc) for x in windowed]
    times_ok = [x for x in times if x is not None]
    if len(times_ok) >= 2:
        dur_min = int((max(times_ok) - min(times_ok)).total_seconds() / 60)
    else:
        dur_min = 0
    status_confidence = 0.55
    if status in {"LIKELY_SERVER_MAINTENANCE", "CONFIRMED_SERVER_MAINTENANCE", "XIAOMI_DOWN", "STABLE_SERVER_FAILURE"}:
        status_confidence = 0.75 if confirmed_runs <= 1 else 0.85
        if status in {"XIAOMI_DOWN", "STABLE_SERVER_FAILURE"}:
            status_confidence = 0.9
    elif status == "STATE_TRANSITION_MAINTENANCE_TO_OK":
        status_confidence = 0.88
    elif status in {"NORMAL_OPERATION", "NORMAL"}:
        status_confidence = 0.92
    elif status in {"NETWORK_ENVIRONMENT_UNSTABLE", "INTERMITTENT_NETWORK"}:
        status_confidence = 0.72
    elif status == "NOT_ELIGIBLE_FOR_UNLOCK":
        status_confidence = 0.9
    decay_applied = 0.0
    freshness_minutes: Optional[int] = None
    server_seen_times = [
        parse_iso_utc(x.ts_utc)
        for x in windowed
        if x.diagnosis == "REAL_SERVER_MAINTENANCE" and x.server_authority and x.cloud_code == "30003"
    ]
    server_seen_ok = [x for x in server_seen_times if x is not None]
    if server_seen_ok:
        freshness_minutes = int((now_ts - max(server_seen_ok)).total_seconds() / 60)
        if freshness_minutes > 20:
            decay_applied = 0.1
            status_confidence = max(0.05, status_confidence - decay_applied)
    last5 = recent5
    trend_last5 = [x.diagnosis for x in last5]
    if len(set(trend_last5)) <= 1:
        trend_stability = "consistent"
    elif len(set(trend_last5[-3:])) <= 1 and len(trend_last5) >= 3:
        trend_stability = "mostly_consistent"
    else:
        trend_stability = "mixed"
    if (
        len(trend_last5) >= 3
        and trend_stability == "consistent"
        and trend_last5[-1] == "REAL_SERVER_MAINTENANCE"
    ):
        status = "STABLE_SERVER_FAILURE"
    if observed_runs >= 3 and trend_stability in {"consistent", "mostly_consistent"}:
        status_confidence = min(0.99, status_confidence + 0.05)
    retry_hint: Optional[str] = None
    if freshness_minutes is not None and freshness_minutes < 2 and status in {
        "LIKELY_SERVER_MAINTENANCE",
        "CONFIRMED_SERVER_MAINTENANCE",
        "XIAOMI_DOWN",
        "STABLE_SERVER_FAILURE",
    }:
        retry_hint = "Recent server-maintenance signal observed (<2 min). Retry later instead of immediate repeated attempts."

    return GlobalTrend(
        status=status,
        confirmed_runs=confirmed_runs,
        observed_runs=observed_runs,
        duration_minutes=dur_min,
        state_transition=state_transition,
        window_minutes=max(1, window_minutes),
        trend_last5=trend_last5,
        trend_stability=trend_stability,
        status_confidence=round(status_confidence, 2),
        freshness_minutes=freshness_minutes,
        decay_applied=decay_applied,
        retry_hint=retry_hint,
        weighted_confirmed_runs=round(weighted_confirmed, 2),
        weighted_observed_runs=round(weighted_observed, 2),
    )


def apply_history_override(
    classification: Classification,
    global_trend: Optional[GlobalTrend],
) -> Classification:
    if global_trend is None:
        return classification
    if global_trend.status in {"XIAOMI_DOWN", "CONFIRMED_SERVER_MAINTENANCE", "STABLE_SERVER_FAILURE"}:
        classification = _apply_server_policy_override(
            classification,
            reason="history override: repeated server-maintenance trend is authoritative",
            layer="server",
            trust_level="strong",
            confidence_floor=0.85,
            conflict_resolution="server_wins",
            correlation_flag="history_override",
        )
    return classification


def _apply_server_policy_override(
    classification: Classification,
    *,
    reason: str,
    layer: Literal["server", "business_bind", "business_unlock", "transport", "network"],
    trust_level: str,
    confidence_floor: float,
    conflict_resolution: str,
    action: Optional[str] = None,
    action_message: Optional[str] = None,
    retry_after_sec: Optional[int] = None,
    conflict_reason: Optional[str] = None,
    correlation_flag: Optional[str] = None,
) -> Classification:
    classification.label = "REAL_SERVER_MAINTENANCE"
    classification.root_cause = "server"
    classification.server_authority = True
    classification.server_trust_level = trust_level
    classification.layer = layer
    classification.truth_layer = {
        "server": True,
        "network": False,
        "device": False,
        "authorization": False,
    }
    if classification.network_state in {"stable", "ok"}:
        classification.network_state = "secondary"
    elif classification.network_state not in {"degraded", "failing", "secondary"}:
        classification.network_state = "secondary"
    if "network_noise" not in classification.side_effects:
        classification.side_effects.append("network_noise")
    classification.conflict = True
    classification.conflict_type = "network_noise"
    classification.conflict_resolution = conflict_resolution
    classification.conflict_reason = conflict_reason or reason
    classification.confidence = max(classification.confidence, confidence_floor)
    classification.confidence_level = "CONFIRMED" if classification.confidence > 0.85 else "LIKELY"
    classification.meaning = "Server-side maintenance/degradation is the most reliable explanation for bind failure."
    classification.internal_label = "bind_failure_server"
    if action is not None:
        classification.action = action
    if action_message is not None:
        classification.action_message = action_message
    if retry_after_sec is not None and classification.retry_after_sec is None:
        classification.retry_after_sec = retry_after_sec
    if correlation_flag and correlation_flag not in classification.correlation_flags:
        classification.correlation_flags.append(correlation_flag)
    return classification


def apply_sticky_server_truth(classification: Classification, parsed: ParsedEvidence) -> Classification:
    for ev in parsed.xiaomi_json_aggregates:
        if ev.code == "30003":
            classification.server_authority = True
            classification.server_trust_level = "strong"
            if classification.root_cause != "server":
                classification.root_cause = "server"
                classification.truth_layer["server"] = True
            if classification.network_state in {"degraded", "failing"}:
                classification.network_state = "secondary"
            if classification.conflict_resolution == "none":
                classification.conflict_resolution = "server_wins"
            if "sticky_server_truth" not in classification.correlation_flags:
                classification.correlation_flags.append("sticky_server_truth")
            break
    return classification


def detect_silent_block(
    parsed: ParsedEvidence,
    classification: Classification,
    domain_checks: list[DomainCheck],
) -> Classification:
    network_ok = is_server_response_valid(domain_checks)
    has_server_response = len(parsed.xiaomi_json_aggregates) > 0
    has_timeouts = any("timeout" in exc.lower() for exc in parsed.exceptions)

    if (
        network_ok
        and has_timeouts
        and not has_server_response
        and classification.label in {"NETWORK_DISTORTION", "SERVER_DEGRADED_NO_RESPONSE", "AMBIGUOUS"}
    ):
        classification.label = "POSSIBLE_SERVER_RATE_LIMIT"
        classification.root_cause = "server"
        classification.server_trust_level = "inferred"
        classification.layer = "business_bind"
        classification.action = "WAIT_AND_RETRY"
        classification.action_message = "Possible quota / anti-bot. Retry later."
        classification.conflict_resolution = "server_wins"
        if "silent_server_block" not in classification.correlation_flags:
            classification.correlation_flags.append("silent_server_block")

    return classification


def apply_truth_priority(
    classification: Classification,
    parsed: ParsedEvidence,
    global_trend: Optional[GlobalTrend],
) -> Classification:
    # 1) Hard truth from explicit Xiaomi response.
    for ev in parsed.xiaomi_json_aggregates:
        if ev.code == "30003":
            return _apply_server_policy_override(
                classification,
                reason="explicit Xiaomi code=30003 is authoritative",
                layer="business_bind",
                trust_level="strong",
                confidence_floor=0.90,
                conflict_resolution="server_wins",
                correlation_flag="truth_priority_30003",
            )

    # 2) Trend-based truth override.
    if global_trend is None:
        return classification
    if global_trend.status in {"XIAOMI_DOWN", "CONFIRMED_SERVER_MAINTENANCE", "STABLE_SERVER_FAILURE"}:
        classification = _apply_server_policy_override(
            classification,
            reason="trend override: confirmed maintenance trend beats current network noise",
            layer="server",
            trust_level="strong",
            confidence_floor=0.85,
            conflict_resolution="trend_override",
            action="WAIT",
            action_message="Xiaomi servers under maintenance trend. Retry in 30-60 minutes.",
            retry_after_sec=random.randint(1200, 3600),
            correlation_flag="truth_priority_trend",
        )
    return classification


def apply_global_truth(
    classification: Classification,
    parsed: ParsedEvidence,
    global_status: Optional[dict[str, Any]],
) -> Classification:
    has_server_truth = any(ev.code == "30003" for ev in parsed.xiaomi_json_aggregates)
    trend_says_down = bool(
        global_status
        and global_status.get("status") in {"XIAOMI_DOWN", "CONFIRMED_SERVER_MAINTENANCE", "STABLE_SERVER_FAILURE"}
    )
    if not (has_server_truth or trend_says_down):
        return classification
    return _apply_server_policy_override(
        classification,
        reason="server truth override: maintenance signal/trend takes priority over network noise",
        layer="server",
        trust_level="strong",
        confidence_floor=0.85,
        conflict_resolution="server_truth_override",
        action="WAIT",
        action_message="Xiaomi servers under maintenance. Retry in 30-60 min.",
        retry_after_sec=random.randint(1200, 3600),
        correlation_flag="global_truth_override",
    )


def finalize_decision(report: DiagnosisReport) -> DiagnosisReport:
    cls = report.classification
    # Stage contract:
    # - finalize normalizes output fields only
    # - finalize must never mutate inferred root_cause
    root_cause_before = cls.root_cause
    host_net_health = evaluate_network_health(report.host_domain_checks)
    profile_ok_ratio = _parse_ratio_percent(cls.network_profile.get("ok_ratio"))
    profile_healthy = cls.network_profile.get("healthy") == "yes"
    network_valid = bool(
        host_net_health["healthy"]
        or profile_healthy
        or profile_ok_ratio >= 0.60
    )

    if cls.confidence > 0.85:
        cls.confidence_level = "CONFIRMED"
    elif cls.confidence > 0.65:
        cls.confidence_level = "LIKELY"
    else:
        cls.confidence_level = "UNCERTAIN"

    if "final_network_health" not in cls.network_profile:
        cls.network_profile["final_network_health"] = "healthy" if network_valid else "degraded"
    cls.network_profile["final_layer_priority"] = str(LAYER_PRIORITY.get(cls.layer, 0))
    cls.network_profile["finalized"] = "yes"
    cls.network_profile["stage_owner"] = "finalize"

    if cls.root_cause != root_cause_before:
        cls.root_cause = root_cause_before
        if "finalize_root_cause_guard" not in cls.correlation_flags:
            cls.correlation_flags.append("finalize_root_cause_guard")

    return report


def apply_policy_layer(
    classification: Classification,
    parsed: ParsedEvidence,
    domain_checks: list[DomainCheck],
    global_trend: Optional[GlobalTrend],
    global_status: Optional[dict[str, Any]],
    recent_history: Optional[list[HistoryEntry]] = None,
) -> Classification:
    # Stage contract:
    # - policy layer may override label/layer/root_cause by hard truth rules
    status = (global_status or {}).get("status")
    has_server_truth = any(ev.code == "30003" for ev in parsed.xiaomi_json_aggregates)
    host_net_health = evaluate_network_health(domain_checks)
    profile_ok_ratio = _parse_ratio_percent(classification.network_profile.get("ok_ratio"))
    profile_healthy = classification.network_profile.get("healthy") == "yes"
    network_valid = bool(
        host_net_health["healthy"]
        or profile_healthy
        or profile_ok_ratio >= 0.60
    )
    business_priority = LAYER_PRIORITY["business_bind"]
    server_priority = LAYER_PRIORITY["server"]

    classification = detect_silent_block(parsed, classification, domain_checks)
    classification = apply_truth_priority(classification, parsed, global_trend)
    classification = apply_global_truth(classification, parsed, global_status)
    classification = apply_history_override(classification, global_trend)
    if status in ("XIAOMI_DOWN", "CONFIRMED_SERVER_MAINTENANCE", "STABLE_SERVER_FAILURE"):
        classification = _apply_server_policy_override(
            classification,
            reason="global status override: confirmed maintenance trend takes priority",
            layer="server",
            trust_level="strong",
            confidence_floor=0.85,
            conflict_resolution="global_override",
            action="WAIT",
            action_message="Xiaomi servers under maintenance. Retry in 30-60 min.",
            retry_after_sec=random.randint(1200, 3600),
            correlation_flag="finalize_decision_global",
        )
    if has_server_truth and network_valid:
        classification = _apply_server_policy_override(
            classification,
            reason="server truth override: maintenance signal/trend takes priority",
            layer="business_bind",
            trust_level="hard",
            confidence_floor=0.85,
            conflict_resolution="server_truth",
            action="WAIT",
            action_message="Xiaomi servers under maintenance. Retry in 30-60 min.",
            retry_after_sec=random.randint(1200, 3600),
            correlation_flag="finalize_decision_server",
        )
    current_layer_priority = LAYER_PRIORITY.get(classification.layer, 0)
    if (
        classification.label == "NETWORK_DISTORTION"
        and network_valid
        and not parsed.xiaomi_json_events
        and not parsed.bind_success_detected
        and current_layer_priority <= business_priority
    ):
        classification.label = "POSSIBLE_SERVER_RATE_LIMIT"
        classification.root_cause = "server"
        classification.server_trust_level = "inferred"
        classification.layer = "business_bind"
        classification.action = "WAIT_AND_RETRY"
        classification.action_message = "Possible Xiaomi rate limit / quota / anti-bot"
        if "network_noise" not in classification.side_effects and classification.network_state != "ok":
            classification.side_effects.append("network_noise")
        if "finalize_decision_silent_block" not in classification.correlation_flags:
            classification.correlation_flags.append("finalize_decision_silent_block")
    current_layer_priority = LAYER_PRIORITY.get(classification.layer, 0)
    if classification.server_authority or current_layer_priority >= server_priority:
        if classification.root_cause not in {"server", "rate_limit", "server_degradation"}:
            classification.root_cause = "server"
            classification.truth_layer = {
                "server": True,
                "network": False,
                "device": False,
                "authorization": False,
            }
    if recent_history and global_trend and global_trend.freshness_minutes is not None and global_trend.freshness_minutes <= 20:
        if any(x.cloud_code == "30003" for x in recent_history[-5:]):
            classification = apply_sticky_server_truth(classification, parsed)
    if classification.server_authority:
        if classification.network_state not in {"degraded", "failing", "secondary"}:
            classification.network_state = "degraded"
        if classification.conflict_resolution == "none":
            classification.conflict_resolution = "server_wins"
    classification.network_profile["stage_owner"] = "policy_layer"
    return classification


# =========================
# CLI orchestration
# =========================


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="xiaomi_unlock_assistant.py",
        description="Diagnostic assistant for Xiaomi Mi Unlock account/device bind failures.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    diagnose = sub.add_parser("diagnose-bind", help="Run bind failure diagnostics")
    diagnose.add_argument("--serial", default=None, help="ADB serial if multiple devices are connected")
    diagnose.add_argument("--duration", type=int, default=140, help="Max capture duration in seconds (default: 140; configurable)")
    wait_group = diagnose.add_mutually_exclusive_group()
    wait_group.add_argument("--wait-for-event", dest="wait_for_event", action="store_true", default=True, help="Event-driven mode (default: enabled)")
    wait_group.add_argument("--no-wait-for-event", dest="wait_for_event", action="store_false", help="Disable wait prompt and capture immediately")
    diagnose.add_argument("--pre-seconds", type=int, default=8, help="Ring-buffer pre-trigger window in seconds")
    diagnose.add_argument("--post-seconds", type=int, default=20, help="Post-trigger capture window in seconds")
    diagnose.add_argument("--arm-countdown", type=int, default=3, help="Countdown before arming capture after Enter (default: 3)")
    diagnose.add_argument("--domains", nargs="*", default=DEFAULT_DOMAINS, help="Domains for host DNS/TLS checks")
    diagnose.add_argument("--output-dir", default=None, help="Output directory (used only when --save/--save-logcat/--json)")
    diagnose.add_argument("--phone-net-check", action="store_true", help="Run optional adb shell ping/nslookup checks")
    diagnose.add_argument("--save", action="store_true", help="Save human-readable report (txt)")
    diagnose.add_argument("--save-logcat", action="store_true", help="Save logcat capture")
    diagnose.add_argument("--json", action="store_true", help="Save machine-readable JSON report")
    diagnose.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    diagnose.add_argument("--minimal", action="store_true", help="Print compact one-line status output")
    diagnose.add_argument(
        "--history-window-minutes",
        type=int,
        default=DEFAULT_HISTORY_WINDOW_MINUTES,
        help="History window used for global trend verdict (default: 30)",
    )
    history_group = diagnose.add_mutually_exclusive_group()
    history_group.add_argument("--history", dest="history", action="store_true", default=True, help="Enable run history/trend memory (default: enabled)")
    history_group.add_argument("--no-history", dest="history", action="store_false", help="Disable history/trend memory")
    diagnose.add_argument("--history-file", default=None, help="Custom JSONL file path for run history")
    diagnose.add_argument("--debug", action="store_true", help="Verbose debug prints")

    return parser.parse_args(argv)


def debug_print(enabled: bool, msg: str) -> None:
    if enabled:
        print(f"[debug] {msg}")


def should_save_outputs(args: argparse.Namespace) -> bool:
    return bool(args.save or args.save_logcat or args.json)


def resolve_output_dir(args: argparse.Namespace, base_dir: Optional[Path] = None) -> Optional[Path]:
    if not should_save_outputs(args):
        return None
    if args.output_dir:
        return Path(args.output_dir)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    root = base_dir or Path.cwd()
    return root / f"xiaomi_diagnose_{ts}"


def _arming_countdown(seconds: int, color_enabled: bool) -> None:
    if seconds <= 0:
        return
    print(ansi(f"Arming capture in {seconds}s...", "33", color_enabled))
    for left in range(seconds, 0, -1):
        print(ansi(f"  {left}...", "2;37", color_enabled))
        time.sleep(1)


def run_diagnose_bind(args: argparse.Namespace) -> int:
    adb = ADBManager(serial=args.serial, debug=args.debug)
    serial = adb.resolve_serial()
    use_color = terminal_color_enabled(args.no_color)
    render_initial_bind_panel(tool_version=TOOL_VERSION, serial=serial, created_at_utc=now_utc_iso(), color_enabled=use_color)

    out_dir = resolve_output_dir(args)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
    log_path: Optional[Path] = (out_dir / "logcat_capture.txt") if (out_dir and args.save_logcat) else None

    debug_print(args.debug, "Collecting device snapshot")
    device = collect_device_snapshot(adb)

    debug_print(args.debug, "Running host DNS/TLS checks")
    domain_checks = host_network_checks(args.domains)

    phone_checks: list[OptionalPhoneNetworkCheck] = []
    if args.phone_net_check:
        debug_print(args.debug, "Running optional phone network checks")
        phone_checks = phone_optional_network_checks(adb, args.domains)

    detector = EventDetector(EVENT_PATTERNS)
    streamer = LogcatStreamer(adb, debug=args.debug)

    # Avoid stale logs from older sessions
    debug_print(args.debug, "Clearing existing logcat buffer")
    adb.clear_logcat()

    if args.wait_for_event:
        print(f"\n{ansi('Event-driven mode enabled.', '1;33', use_color)}")
        print(ansi("1) Open phone: Settings -> Mi Unlock Status", "36", use_color))
        print(ansi("2) Navigate to Add account and device", "36", use_color))
        print(ansi("3) Press Enter to ARM log capture; wait for READY prompt, then tap on phone once.", "36", use_color))
        print(ansi("Tip: tune timing via --duration and --arm-countdown.", "2;37", use_color))
        input(ansi("Press Enter to arm capture... ", "1;35", use_color))
        _arming_countdown(args.arm_countdown, use_color)

    print(ansi("Capturing logcat and waiting for trigger event...", "1;34", use_color))
    capture = streamer.capture_event_driven(
        detector=detector,
        duration_s=args.duration,
        pre_seconds=args.pre_seconds,
        post_seconds=args.post_seconds,
        output_path=log_path,
        announce_ready=args.wait_for_event,
        color_enabled=use_color,
    )

    parsed = parse_evidence(capture.all_lines)
    classifier = Classifier()
    classification = classifier.classify(capture, parsed, domain_checks, device, phone_checks)
    network_health = evaluate_network_health(domain_checks)
    classification = decide_root_cause(parsed, classification, network_health, capture.events)
    event_flow = summarize_event_flow(capture.events)
    global_status_dict: Optional[dict[str, Any]] = None
    trend_obj: Optional[GlobalTrend] = None
    history_path: Optional[Path] = None
    history_entries: Optional[list[HistoryEntry]] = None
    if args.history:
        history_path = resolve_history_path(args)
        debug_print(args.debug, f"Using history file: {history_path}")
        history_entries = load_history_entries(history_path)
        prev_entry = history_entries[-1] if history_entries else None
        current_entry = build_history_entry(serial=serial, classification=classification, parsed=parsed, prev_entry=prev_entry)
        history_entries.append(current_entry)
        trend = assess_global_trend(
            history=history_entries,
            current=current_entry,
            window_minutes=args.history_window_minutes,
        )
        trend_obj = trend
        global_status_dict = dataclasses.asdict(trend)
        classification = decide_root_cause(
            parsed,
            classification,
            network_health,
            capture.events,
            recent_history=history_entries[-10:],
            global_trend=trend_obj,
        )
        if trend.status == "NOT_ELIGIBLE_FOR_UNLOCK":
            if classification.action not in {"APPLY_IN_MI_COMMUNITY"}:
                classification.action = "APPLY_IN_MI_COMMUNITY"
                classification.action_message = "Authorization is required. Apply in Mi Community and retry after approval."
        elif trend.status in {"XIAOMI_DOWN", "CONFIRMED_SERVER_MAINTENANCE", "LIKELY_SERVER_MAINTENANCE", "STABLE_SERVER_FAILURE"}:
            if classification.action not in {"WAIT", "WAIT_AND_RETRY", "WAIT_AND_RETRY_LATER"}:
                classification.action = "WAIT"
            if not classification.action_message or classification.action_message == "Review evidence and retry diagnostics.":
                classification.action_message = trend.retry_hint or "Server maintenance likely. Retry in ~30-60 minutes."
            if classification.retry_after_sec is None:
                classification.retry_after_sec = random.randint(1200, 3600)
    classification = apply_policy_layer(
        classification,
        parsed,
        domain_checks,
        trend_obj,
        global_status_dict,
        recent_history=history_entries,
    )
    if args.history and history_path is not None and history_entries is not None and history_entries:
        # Persist finalized classification (after all overrides), not pre-override draft.
        prev_entry = history_entries[-2] if len(history_entries) >= 2 else None
        history_entries[-1] = build_history_entry(serial=serial, classification=classification, parsed=parsed, prev_entry=prev_entry)
        final_trend = assess_global_trend(
            history=history_entries,
            current=history_entries[-1],
            window_minutes=args.history_window_minutes,
        )
        global_status_dict = dataclasses.asdict(final_trend)
        classification = apply_policy_layer(
            classification,
            parsed,
            domain_checks,
            final_trend,
            global_status_dict,
            recent_history=history_entries,
        )
        prev_entry = history_entries[-2] if len(history_entries) >= 2 else None
        history_entries[-1] = build_history_entry(serial=serial, classification=classification, parsed=parsed, prev_entry=prev_entry)
        final_trend = assess_global_trend(
            history=history_entries,
            current=history_entries[-1],
            window_minutes=args.history_window_minutes,
        )
        global_status_dict = dataclasses.asdict(final_trend)
        try:
            persist_history_entries(history_path, history_entries)
        except Exception as exc:
            debug_print(args.debug, f"History persist failed: {exc}")

    report = DiagnosisReport(
        created_at_utc=now_utc_iso(),
        tool_version=TOOL_VERSION,
        serial=serial,
        device_snapshot=device,
        host_domain_checks=domain_checks,
        phone_network_checks=phone_checks,
        capture=capture,
        parsed=parsed,
        classification=classification,
        event_flow=event_flow,
        global_status=global_status_dict,
    )
    report = finalize_decision(report)

    if args.minimal:
        minimal_rendered = render_minimal_line(report, color_enabled=not args.no_color)
        if not minimal_rendered:
            print(render_human_report(report))
    else:
        rich_rendered = render_human_report_rich(report, color_enabled=not args.no_color)
        if not rich_rendered:
            print(render_human_report(report))
    saved_files: list[Path] = []
    if out_dir is not None:
        saved_files.extend(
            save_report_files(
                report=report,
                out_dir=out_dir,
                save_human=args.save,
                save_json=args.json,
            )
        )
        if args.save_logcat and capture.log_path:
            saved_files.append(Path(capture.log_path))

    if saved_files:
        print(f"\n{ansi('=== Saved files ===', '1;35', use_color)}")
        for path in saved_files:
            print(f"{ansi('-', '2;37', use_color)} {ansi(str(path), '33', use_color)}")
    else:
        print(f"\n{ansi('=== Saved files ===', '1;35', use_color)}")
        print(f"{ansi('-', '2;37', use_color)} {ansi('none (enable with --save, --save-logcat, --json)', '2;37', use_color)}")

    return 0


def _build_self_check_classification() -> Classification:
    return Classification(
        label="AMBIGUOUS",
        confidence=0.4,
        root_evidence=[],
        confidence_explanation=[],
        secondary=[],
        secondary_label=None,
        internal_label="bind_failure_network",
        conflict=False,
        conflict_reason=None,
        correlation_flags=[],
        meaning="self-check",
        filtered_noise=[],
        scores={
            "bind_failure_network": 0,
            "bind_failure_server": 0,
            "bind_failure_account_state": 0,
            "unlock_authorization_required": 0,
        },
        best_score=0,
        second_score=0,
        confidence_floor=0.0,
        confidence_k=10,
        terminal_override_applied=False,
        terminal_override_reason=None,
    )


def _run_local_self_checks() -> None:
    healthy_checks = [
        DomainCheck(domain="account.xiaomi.com", dns_ok=True, resolved_ips=["1.1.1.1"], dns_error=None, tls_ok=True, tls_error=None, latency_ms=120),
        DomainCheck(domain="api.io.mi.com", dns_ok=True, resolved_ips=["1.1.1.2"], dns_error=None, tls_ok=True, tls_error=None, latency_ms=150),
        DomainCheck(domain="unlock.update.miui.com", dns_ok=True, resolved_ips=["1.1.1.3"], dns_error=None, tls_ok=True, tls_error=None, latency_ms=110),
    ]
    degraded_checks = [
        DomainCheck(domain="account.xiaomi.com", dns_ok=False, resolved_ips=[], dns_error="nx", tls_ok=False, tls_error="dns", latency_ms=None),
        DomainCheck(domain="api.io.mi.com", dns_ok=True, resolved_ips=["1.1.1.2"], dns_error=None, tls_ok=False, tls_error="timeout", latency_ms=None, tls_failure_type="timeout"),
        DomainCheck(domain="unlock.update.miui.com", dns_ok=True, resolved_ips=["1.1.1.3"], dns_error=None, tls_ok=False, tls_error="reset", latency_ms=None, tls_failure_type="connection_reset"),
    ]

    parsed_server = ParsedEvidence(
        urls_redacted=[],
        domains_trusted=[],
        domains_rejected=[],
        http_statuses=[],
        non_http_status_hints=[],
        exceptions=[],
        xiaomi_related_lines=[],
        xiaomi_json_events=['{"code":30003}'],
        xiaomi_json_aggregates=[XiaomiJsonAggregate(code="30003", desc="system is being upgraded", count=3, first_seen="t1", last_seen="t2")],
        bind_success_detected=False,
        success_evidence=[],
    )
    cls_server = _build_self_check_classification()
    cls_server.scores["bind_failure_server"] = 18
    cls_server.scores["bind_failure_network"] = 6
    cls_server.label = "NETWORK_DISTORTION"
    cls_server = decide_root_cause(parsed_server, cls_server, evaluate_network_health(healthy_checks), [])
    assert cls_server.root_cause == "server"

    parsed_silent = ParsedEvidence(
        urls_redacted=[],
        domains_trusted=[],
        domains_rejected=[],
        http_statuses=[],
        non_http_status_hints=[],
        exceptions=["SocketTimeoutException"],
        xiaomi_related_lines=[],
        xiaomi_json_events=[],
        xiaomi_json_aggregates=[],
        bind_success_detected=False,
        success_evidence=[],
    )
    cls_silent = _build_self_check_classification()
    cls_silent.label = "NETWORK_DISTORTION"
    cls_silent.scores["bind_failure_network"] = 9
    cls_silent = apply_policy_layer(cls_silent, parsed_silent, healthy_checks, None, None, None)
    assert cls_silent.label == "POSSIBLE_SERVER_RATE_LIMIT"

    cls_network = _build_self_check_classification()
    cls_network.label = "NETWORK_DISTORTION"
    cls_network.scores["bind_failure_network"] = 16
    cls_network = decide_root_cause(parsed_silent, cls_network, evaluate_network_health(degraded_checks), [])
    assert cls_network.root_cause == "network"


def main(argv: Optional[list[str]] = None) -> int:
    if os.environ.get("XIAOMI_ASSISTANT_SELF_CHECK") == "1":
        _run_local_self_checks()
        print("Self-checks passed", file=sys.stderr)
        return 0

    args = parse_args(argv)

    try:
        if args.command == "diagnose-bind":
            return run_diagnose_bind(args)
        raise ToolError(f"Unknown command: {args.command}")
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        return 130
    except ToolError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
