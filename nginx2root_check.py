#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nginx2root exposure checker.

Black-box, non-destructive check for the nginx vulnerabilities published by
Xint on 2026-11-18 (fixed in nginx 1.31.9 and 1.30.7):

    CVE-2026-123007  HTTP/2 flow-control window overflow (RCE, critical)
    CVE-2026-123634  use-after-free in resolver (request-time DNS + subrequest)
    CVE-2026-123633  use-after-free in HTTP/2 (needs upstream proxying)
    CVE-2026-121810  use-after-free in HTTP/3 (needs upstream proxying)
    CVE-2026-113425  use-after-free in mail proxy (proxy + auth_http)

The checker only performs:
  * a TLS handshake with ALPN ("h2", "http/1.1") to see what is negotiated,
  * one ordinary HTTP/1.1 HEAD/GET request to fingerprint the server,
  * one minimal HTTP/2 request (preface + SETTINGS + HEADERS), no flow-control
    tricks, no WINDOW_UPDATE flood, no RST_STREAM -- i.e. nothing that could
    trigger the actual bug,
  * an optional QUIC version-negotiation datagram on UDP/443.

It never attempts to exploit anything. A remote check cannot prove that a
distribution package is unpatched (backports) and cannot see the
`resolver`/`mirror`/`mail` configuration, so several verdicts are necessarily
"unknown".
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as _dt
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

CHECKER_VERSION = "0.1.0"
USER_AGENT = "nginx2root-check/%s" % CHECKER_VERSION

DEFAULT_TIMEOUT = 5.0
MAX_BODY = 16 * 1024
MAX_H2_FRAMES = 64
MAX_H2_BYTES = 64 * 1024

# --------------------------------------------------------------------------
# Vulnerability metadata
# --------------------------------------------------------------------------

FIXED_MAINLINE = (1, 31, 9)
FIXED_STABLE_130 = (1, 30, 7)
LAST_VULNERABLE = (1, 31, 8)

ADVISORY_URL = "https://nginx.org/en/security_advisories.html"
UBUNTU_USN = "https://ubuntu.com/security/notices/USN-8955-1"

CVE_META: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2026-123007",
        "title": "HTTP/2 flow-control window overflow",
        "min_affected": (1, 9, 5),
        "needs": "h2",
        "config_only": False,
        "severity": "critical",
        "f5": "https://my.f5.com/manage/s/article/K000163926",
    },
    {
        "cve": "CVE-2026-123634",
        "title": "use-after-free in resolver (request-time DNS + subrequest)",
        "min_affected": (0, 6, 18),
        "needs": "resolver",
        "config_only": True,
        "severity": "medium",
        "f5": "https://my.f5.com/manage/s/article/K000163925",
    },
    {
        "cve": "CVE-2026-123633",
        "title": "use-after-free in HTTP/2",
        "min_affected": (1, 19, 7),
        "needs": "h2",
        "config_only": False,
        "severity": "medium",
        "f5": "https://my.f5.com/manage/s/article/K000163928",
    },
    {
        "cve": "CVE-2026-121810",
        "title": "use-after-free in HTTP/3",
        "min_affected": (1, 25, 0),
        "needs": "h3",
        "config_only": False,
        "severity": "medium",
        "f5": "https://my.f5.com/manage/s/article/K000163927",
    },
    {
        "cve": "CVE-2026-113425",
        "title": "use-after-free in mail proxy",
        "min_affected": (0, 0, 0),
        "needs": "mail",
        "config_only": True,
        "severity": "major",
        "f5": "https://my.f5.com/manage/s/article/K000163931",
    },
]

# Verdicts (machine readable, keep stable)
LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
PATCHED = "PATCHED"
MITIGATED = "MITIGATED"
NOT_AFFECTED = "NOT_AFFECTED"
NOT_APPLICABLE = "NOT_APPLICABLE"
INCONCLUSIVE = "INCONCLUSIVE"
UNKNOWN = "UNKNOWN"

VERDICT_COLORS = {
    LIKELY_VULNERABLE: "\033[1;31m",
    INCONCLUSIVE: "\033[1;33m",
    UNKNOWN: "\033[0;33m",
    MITIGATED: "\033[0;36m",
    PATCHED: "\033[0;32m",
    NOT_AFFECTED: "\033[0;32m",
    NOT_APPLICABLE: "\033[0;32m",
}

# Human readable statuses and actions
STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAILED = "CHECK_FAILED"

STATUS_LABELS = {
    STATUS_OK: "ВЫПОЛНЕНА",
    STATUS_PARTIAL: "ЧАСТИЧНО",
    STATUS_FAILED: "НЕ ВЫПОЛНЕНА",
}

VERDICT_LABELS = {
    LIKELY_VULNERABLE: "ВЕРОЯТНО УЯЗВИМ",
    PATCHED: "ИСПРАВЛЕНО",
    MITIGATED: "ПУТЬ АТАКИ ЗАКРЫТ",
    NOT_AFFECTED: "НЕ ЗАТРОНУТ",
    NOT_APPLICABLE: "НЕ ПРИМЕНИМО",
    INCONCLUSIVE: "НЕОПРЕДЕЛЁННО",
    UNKNOWN: "ПРОВЕРИТЬ НА СЕРВЕРЕ",
}

ACTION_BY_VERDICT = {
    LIKELY_VULNERABLE: ("UPDATE", "обновить nginx до 1.31.9/1.30.7"),
    PATCHED: ("NONE", "ничего не делать"),
    MITIGATED: ("NONE", "ничего не делать (обновить при возможности)"),
    NOT_AFFECTED: ("NONE", "ничего не делать"),
    NOT_APPLICABLE: ("NONE", ""),
    INCONCLUSIVE: ("MANUAL", "проверить вручную: CDN / бэкпорт / ошибка связи"),
    UNKNOWN: ("CHECK_HOST", "проверить конфигурацию на сервере"),
}

SUMMARY_COLORS = {
    "RISK": "\033[1;31m",
    "INCONCLUSIVE": "\033[1;33m",
    "OK": "\033[0;32m",
    "FAILED": "\033[1;31m",
}

FAILURE_ADVICE = {
    "DNS": "проверить домен и DNS, затем повторить проверку",
    "TIMEOUT": "проверить сеть/фильтрацию, повторить с другой точки",
    "CONNECT": "проверить, что сервис слушает порт и firewall его не блокирует",
    "TLS": "проверить TLS на сервере; для самоподписанного запускать без --verify",
    "TLS_CERT": "проверить сертификат; для самоподписанного запускать без --verify",
    "NETWORK": "проверить сеть и повторить с другой точки",
    "HTTP": "проверить, что сервер отвечает на HTTP-запросы",
}

# --------------------------------------------------------------------------
# Version helpers
# --------------------------------------------------------------------------

# Vendors and patches often change the product token: nginx-reuseport/1.30.7,
# nginx-naxsi/1.24.0, nginx-extras/1.18.0. The core version is still the tail.
_NGINX_VERSION_RE = re.compile(
    r"nginx[-_a-z0-9]*/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE
)
_DISTRO_RE = re.compile(
    r"\((Ubuntu|Debian|Alpine|CentOS|RHEL|Red Hat|Rocky|AlmaLinux|Amazon|SUSE|openSUSE)[^)]*\)",
    re.IGNORECASE,
)


def parse_version(value: str) -> Optional[Tuple[int, int, int]]:
    """Parse a version out of ``nginx/1.24.0``, ``nginx-reuseport/1.30.7`` etc."""
    if not value:
        return None
    match = _NGINX_VERSION_RE.search(value)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def format_version(version: Optional[Tuple[int, int, int]]) -> str:
    if version is None:
        return "?"
    return "%d.%d.%d" % version


def patch_status(
    version: Tuple[int, int, int], min_affected: Tuple[int, int, int]
) -> str:
    """Return PATCHED / VULNERABLE / NOT_AFFECTED / UNKNOWN for a version."""
    if version >= FIXED_MAINLINE:
        return PATCHED
    if version[:2] == (1, 30):
        return PATCHED if version >= FIXED_STABLE_130 else "VULNERABLE"
    if version < min_affected:
        return NOT_AFFECTED
    if version <= LAST_VULNERABLE:
        return "VULNERABLE"
    return "UNKNOWN"


def detect_distro(server_header: str) -> Optional[str]:
    match = _DISTRO_RE.search(server_header or "")
    if not match:
        return None
    return match.group(1)


# OpenResty, Tengine, Angie, Kong and APISIX embed the nginx core, so the same
# nginx CVEs apply. Their Server header does not contain the string "nginx".
NGINX_FAMILY_MARKERS = ("nginx", "openresty", "tengine", "angie", "kong", "apisix")


def is_nginx_family(value: str) -> bool:
    value = (value or "").lower()
    return any(marker in value for marker in NGINX_FAMILY_MARKERS)


# --------------------------------------------------------------------------
# Target / observation model
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Target:
    raw: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def url(self) -> str:
        host = "[%s]" % self.host if ":" in self.host else self.host
        default_port = 443 if self.scheme == "https" else 80
        port = "" if self.port == default_port else ":%d" % self.port
        return "%s://%s%s%s" % (self.scheme, host, port, self.path)

    @property
    def authority(self) -> str:
        host = "[%s]" % self.host if ":" in self.host else self.host
        default_port = 443 if self.scheme == "https" else 80
        return host if self.port == default_port else "%s:%d" % (host, self.port)


def parse_target(raw: str, port_override: Optional[int], path_override: Optional[str]) -> Target:
    raw = raw.strip()
    if not raw:
        raise ValueError("пустой адрес")

    scheme_in_url = "://" in raw
    if scheme_in_url:
        parts = urlsplit(raw)
    else:
        parts = urlsplit("//" + raw, scheme="https")

    scheme = (parts.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ValueError("поддерживаются только http:// и https:// (получено %r)" % scheme)
    if not parts.hostname:
        raise ValueError("не удалось выделить хост из %r" % raw)

    host = parts.hostname
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("некорректный порт: %s" % exc) from exc
    if port is None:
        port = port_override or (443 if scheme == "https" else 80)
    elif port_override:
        port = port_override

    path = path_override or parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    return Target(raw=raw, scheme=scheme, host=host, port=port, path=path)


@dataclasses.dataclass
class Observation:
    target: str
    host: str
    port: int
    scheme: str

    tls_ok: bool = False
    tls_error: Optional[str] = None
    tls_version: Optional[str] = None
    alpn: Optional[str] = None
    cert_verified: Optional[bool] = None

    h2_negotiated: Optional[bool] = None
    h2_functional: Optional[bool] = None
    h2_detail: Optional[str] = None

    h3_altsvc: bool = False
    h3_quic: Optional[bool] = None
    h3_checked: bool = False
    h3_udp_timeout: bool = False
    h3_detail: Optional[str] = None

    http_status: Optional[int] = None
    server_header: Optional[str] = None
    headers: Dict[str, str] = dataclasses.field(default_factory=dict)
    nginx_version: Optional[Tuple[int, int, int]] = None
    nginx_version_raw: Optional[str] = None
    distro: Optional[str] = None
    server_is_nginx: Optional[bool] = None
    cdn: Optional[str] = None
    status: str = STATUS_OK
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    notes: List[str] = dataclasses.field(default_factory=list)

    def as_json(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["nginx_version"] = format_version(self.nginx_version) if self.nginx_version else None
        return data


@dataclasses.dataclass
class Finding:
    cve: str
    title: str
    severity: str
    verdict: str
    reason: str
    reference: str
    verdict_label: str = ""
    action: str = ""
    action_label: str = ""

    def as_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------
# Low-level network helpers
# --------------------------------------------------------------------------


def describe_exception(exc: BaseException) -> Tuple[str, str]:
    """Map a network/TLS exception to a short machine code and a Russian text."""
    if isinstance(exc, socket.gaierror):
        return "DNS", "не удалось разрешить имя (DNS)"
    if isinstance(exc, ConnectionRefusedError):
        return "CONNECT", "соединение отклонено (порт закрыт)"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "TIMEOUT", "таймаут: сервер не отвечает"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS_CERT", "сертификат не прошёл проверку"
    if isinstance(exc, ssl.SSLError):
        return "TLS", "ошибка TLS: %s" % (getattr(exc, "reason", None) or exc)
    if isinstance(exc, ConnectionResetError):
        return "NETWORK", "соединение сброшено"
    if isinstance(exc, OSError):
        return "NETWORK", "сетевая ошибка: %s" % (exc.strerror or exc)
    return "INTERNAL", "внутренняя ошибка: %s" % exc


def resolve_preflight(host: str, port: int) -> Optional[Tuple[str, str]]:
    """Resolve the target before probing; return (code, message) on failure."""
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "DNS", "не удалось разрешить имя (DNS): %s" % host
    except (UnicodeError, OSError) as exc:
        return describe_exception(exc)
    return None


def make_tls_context(alpn: Sequence[str], verify: bool) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    if verify:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
    else:
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(list(alpn))
    return context


def tls_connect(
    host: str,
    port: int,
    timeout: float,
    alpn: Sequence[str],
    verify: bool,
    servername: Optional[str] = None,
) -> ssl.SSLSocket:
    context = make_tls_context(alpn, verify)
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    try:
        return context.wrap_socket(raw, server_hostname=servername or host)
    except Exception:
        raw.close()
        raise


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("соединение закрыто")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------
# TLS / ALPN probe
# --------------------------------------------------------------------------


@dataclasses.dataclass
class TlsProbe:
    ok: bool
    error: Optional[str] = None
    error_code: Optional[str] = None
    version: Optional[str] = None
    alpn: Optional[str] = None
    cert_verified: Optional[bool] = None


def probe_tls(host: str, port: int, timeout: float, verify: bool) -> TlsProbe:
    try:
        sock = tls_connect(host, port, timeout, ("h2", "http/1.1"), verify)
    except Exception as exc:  # noqa: BLE001 - report any handshake failure
        code, message = describe_exception(exc)
        return TlsProbe(ok=False, error=message, error_code=code)
    with sock:
        return TlsProbe(
            ok=True,
            version=sock.version(),
            alpn=sock.selected_alpn_protocol(),
            cert_verified=verify,
        )


# --------------------------------------------------------------------------
# HTTP/1.1 fingerprint
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Http11Probe:
    ok: bool
    error: Optional[str] = None
    error_code: Optional[str] = None
    status: Optional[int] = None
    headers: Dict[str, str] = dataclasses.field(default_factory=dict)
    body: bytes = b""


def _parse_http_response(raw: bytes) -> Tuple[Optional[int], Dict[str, str], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n") if head else []
    status = None
    if lines:
        match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
        if match:
            status = int(match.group(1))
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.strip().lower().decode("latin-1")
        val = value.strip().decode("latin-1")
        headers[key] = "%s, %s" % (headers[key], val) if key in headers else val
    return status, headers, body


def _http11_exchange(host: str, port: int, timeout: float, request: bytes,
                     verify: bool, servername: str, want_body: bool = False) -> bytes:
    sock = tls_connect(host, port, timeout, ("http/1.1",), verify, servername)
    with sock:
        sock.sendall(request)
        chunks: List[bytes] = []
        total = 0
        while total < MAX_BODY:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if not want_body and b"\r\n\r\n" in b"".join(chunks):
                # HEAD responses have no body; stop at the header block.
                break
        return b"".join(chunks)


def probe_http11(
    host: str, port: int, timeout: float, authority: str, path: str, verify: bool
) -> Http11Probe:
    request = (
        "HEAD %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ) % (path, authority, USER_AGENT)
    try:
        raw = _http11_exchange(host, port, timeout, request.encode("latin-1"), verify, host)
    except Exception as exc:  # noqa: BLE001
        code, message = describe_exception(exc)
        return Http11Probe(ok=False, error=message, error_code=code)

    status, headers, body = _parse_http_response(raw)
    if not raw:
        return Http11Probe(ok=False, error="сервер закрыл соединение без ответа",
                           error_code="HTTP")
    if status is None and not headers:
        return Http11Probe(ok=False, error="не удалось разобрать HTTP-ответ",
                           error_code="HTTP")

    # nginx hides the version in 404 pages when server_tokens is off, but the
    # default page still exposes "nginx/<version>" when tokens are on.
    if "server" not in headers or parse_version(headers.get("server", "")) is None:
        probe_path = "/nginx2root-check-%04x" % (os.getpid() & 0xFFFF)
        fallback = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ) % (probe_path, authority, USER_AGENT)
        try:
            raw2 = _http11_exchange(
                host, port, timeout, fallback.encode("latin-1"), verify, host, want_body=True
            )
            status2, headers2, body2 = _parse_http_response(raw2)
            for key, value in headers2.items():
                headers.setdefault(key, value)
            if body2:
                body = body2
            if status is None:
                status = status2
        except Exception:  # noqa: BLE001 - fingerprint is best effort
            pass

    return Http11Probe(ok=True, status=status, headers=headers, body=body)


# --------------------------------------------------------------------------
# HTTP/2 probe (minimal, safe)
# --------------------------------------------------------------------------

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_FRAME_HEADERS = 0x1
H2_FRAME_SETTINGS = 0x4
H2_FRAME_PING = 0x6
H2_FRAME_GOAWAY = 0x7
H2_FLAG_END_STREAM = 0x1
H2_FLAG_ACK = 0x1
H2_FLAG_END_HEADERS = 0x4


def _encode_int(value: int, prefix_bits: int, mask: int) -> bytes:
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes((mask | value,))
    out = bytearray((mask | limit,))
    value -= limit
    while value >= 128:
        out.append((value % 128) + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def _encode_str(value: str) -> bytes:
    data = value.encode("latin-1")
    return _encode_int(len(data), 7, 0x00) + data


def hpack_request_headers(authority: str, user_agent: str = USER_AGENT) -> bytes:
    """HPACK-encode a minimal GET request using the static table only."""
    out = bytearray()
    out.append(0x82)  # :method: GET      (static index 2)
    out.append(0x87)  # :scheme: https    (static index 7)
    out.append(0x84)  # :path: /          (static index 4)
    out += _encode_int(1, 4, 0x00) + _encode_str(authority)   # :authority
    out += _encode_int(58, 4, 0x00) + _encode_str(user_agent)  # user-agent
    return bytes(out)


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type, flags))
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


@dataclasses.dataclass
class H2Probe:
    ok: bool
    negotiated: Optional[str] = None
    settings: bool = False
    response: bool = False
    error: Optional[str] = None
    frames: List[str] = dataclasses.field(default_factory=list)


def probe_h2(
    host: str, port: int, timeout: float, authority: str, verify: bool
) -> H2Probe:
    result = H2Probe(ok=False)
    try:
        sock = tls_connect(host, port, timeout, ("h2",), verify)
    except Exception as exc:  # noqa: BLE001
        result.error = "%s: %s" % (type(exc).__name__, exc)
        return result

    with sock:
        result.negotiated = sock.selected_alpn_protocol()
        if result.negotiated != "h2":
            result.error = "ALPN=%s" % (result.negotiated or "нет")
            return result
        try:
            sock.sendall(H2_PREFACE)
            sock.sendall(h2_frame(H2_FRAME_SETTINGS, 0, 0))
            sock.sendall(
                h2_frame(
                    H2_FRAME_HEADERS,
                    H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS,
                    1,
                    hpack_request_headers(authority),
                )
            )
        except Exception as exc:  # noqa: BLE001
            result.error = "send: %s" % exc
            return result

        deadline = time.monotonic() + timeout
        frames_seen = 0
        bytes_seen = 0
        while frames_seen < MAX_H2_FRAMES and bytes_seen < MAX_H2_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                header = _recv_exact(sock, 9)
            except (socket.timeout, TimeoutError):
                break
            except (ConnectionError, OSError):
                break
            length = int.from_bytes(header[:3], "big")
            frame_type = header[3]
            flags = header[4]
            stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            try:
                payload = _recv_exact(sock, length) if length else b""
            except (ConnectionError, OSError, socket.timeout, TimeoutError):
                break
            frames_seen += 1
            bytes_seen += 9 + length
            result.frames.append("%s/%d" % (_h2_type_name(frame_type), length))

            if frame_type == H2_FRAME_SETTINGS and not flags & H2_FLAG_ACK:
                result.settings = True
                try:
                    sock.sendall(h2_frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0))
                except OSError:
                    pass
            elif frame_type == H2_FRAME_PING and not flags & H2_FLAG_ACK and length == 8:
                try:
                    sock.sendall(h2_frame(H2_FRAME_PING, H2_FLAG_ACK, 0, payload))
                except OSError:
                    pass
            elif frame_type in (H2_FRAME_HEADERS, 0x0) and stream_id == 1:
                if frame_type == H2_FRAME_HEADERS:
                    result.response = True
                if result.settings and result.response:
                    break

        try:
            sock.sendall(h2_frame(H2_FRAME_GOAWAY, 0, 0, struct.pack(">II", 1, 0)))
        except OSError:
            pass

    result.ok = bool(result.settings and result.response)
    if not result.ok and not result.error:
        result.error = "нет ответа на HEADERS (frames: %s)" % (
            ", ".join(result.frames) or "нет"
        )
    return result


def _h2_type_name(frame_type: int) -> str:
    names = {
        0x0: "DATA",
        0x1: "HEADERS",
        0x2: "PRIORITY",
        0x3: "RST_STREAM",
        0x4: "SETTINGS",
        0x5: "PUSH_PROMISE",
        0x6: "PING",
        0x7: "GOAWAY",
        0x8: "WINDOW_UPDATE",
        0x9: "CONTINUATION",
    }
    return names.get(frame_type, "0x%x" % frame_type)


# --------------------------------------------------------------------------
# HTTP/3 / QUIC probe
# --------------------------------------------------------------------------

QUIC_UNSUPPORTED_VERSION = 0x1A2A3A4A  # reserved / greased version


def _encode_varint(value: int) -> bytes:
    if value < 64:
        return bytes((value,))
    if value < 16384:
        return (0x4000 | value).to_bytes(2, "big")
    if value < 1073741824:
        return (0x80000000 | value).to_bytes(4, "big")
    return (0xC000000000000000 | value).to_bytes(8, "big")


def build_quic_vn_probe(size: int = 1200) -> Tuple[bytes, bytes]:
    """Build a QUIC Initial with an unsupported version; return (packet, scid)."""
    dcid = os.urandom(8)
    scid = os.urandom(8)
    payload_len = size - 26  # 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2
    packet = bytearray()
    packet.append(0xC0)  # long header, Initial, fixed bit
    packet += QUIC_UNSUPPORTED_VERSION.to_bytes(4, "big")
    packet.append(len(dcid))
    packet += dcid
    packet.append(len(scid))
    packet += scid
    packet += b"\x00"  # token length
    packet += _encode_varint(payload_len)
    packet += b"\x00" * payload_len
    return bytes(packet), scid


def is_version_negotiation(data: bytes, client_scid: bytes) -> bool:
    if len(data) < 7:
        return False
    if not data[0] & 0x80:
        return False
    if data[1:5] != b"\x00\x00\x00\x00":
        return False
    dcid_len = data[5]
    if len(data) < 6 + dcid_len:
        return False
    return data[6 : 6 + dcid_len] == client_scid


@dataclasses.dataclass
class QuicProbe:
    detected: Optional[bool] = None
    error: Optional[str] = None
    timed_out: bool = False


def probe_quic(host: str, port: int, timeout: float) -> QuicProbe:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except OSError as exc:
        return QuicProbe(detected=None, error="DNS: %s" % exc)
    if not infos:
        return QuicProbe(detected=None, error="DNS: нет адресов")

    family, socktype, proto, _, sockaddr = infos[0]
    packet, scid = build_quic_vn_probe()
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
        sock.send(packet)
        data = sock.recv(1500)
    except (socket.timeout, TimeoutError):
        return QuicProbe(
            detected=False, error="UDP/%.0f: нет ответа" % port, timed_out=True
        )
    except ConnectionRefusedError:
        return QuicProbe(detected=False, error="UDP: port unreachable")
    except OSError as exc:
        return QuicProbe(detected=None, error="UDP: %s" % exc)
    finally:
        sock.close()

    if is_version_negotiation(data, scid):
        return QuicProbe(detected=True)
    # Any response at all means something speaks QUIC on that port.
    return QuicProbe(detected=True, error="ответ не является Version Negotiation")


def parse_altsvc(headers: Dict[str, str]) -> bool:
    value = (headers.get("alt-svc") or "").lower()
    if not value:
        return False
    return bool(re.search(r"(?:^|,)\s*h3(?:-\d+)?\s*=", value))


# --------------------------------------------------------------------------
# Fingerprinting and CDN detection
# --------------------------------------------------------------------------

CDN_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    "Cloudflare": ("cf-ray", "cf-cache-status", "server:cloudflare"),
    "Akamai": ("x-akamai-request-id", "akamai-grn", "server:akamai"),
    "Amazon CloudFront": ("x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront"),
    "Fastly": ("x-fastly-request-id", "fastly-debug-digest", "via:fastly"),
    "Varnish": ("x-varnish", "via:varnish"),
    "Vercel": ("x-vercel-id", "x-vercel-cache"),
    "Netlify": ("x-nf-request-id",),
    "Azure Front Door": ("x-azure-ref", "x-msedge-ref"),
    "Imperva": ("x-iinfo", "server:imperva"),
    "Sucuri": ("x-sucuri-id", "server:sucuri"),
    "Google Cloud": ("x-cloud-trace-context", "server:google frontend", "server:gws"),
}


def detect_cdn(headers: Dict[str, str]) -> Optional[str]:
    haystack = []
    for key, value in headers.items():
        haystack.append("%s:%s" % (key.lower(), value.lower()))
    joined = " | ".join(haystack)
    for name, needles in CDN_SIGNATURES.items():
        if any(needle in joined for needle in needles):
            return name
    return None


def fingerprint(
    host: str, port: int, timeout: float, authority: str, path: str, verify: bool
) -> Http11Probe:
    return probe_http11(host, port, timeout, authority, path, verify)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Options:
    timeout: float = DEFAULT_TIMEOUT
    verify: bool = False
    h2_request: bool = True
    h3: bool = True
    port: Optional[int] = None
    path: Optional[str] = None
    attempts: int = 3


# A stalled handshake is common behind overloaded or filtered servers: TCP
# connects, then no TLS answer. Retrying once or twice distinguishes a flaky
# link from an actually dead host.
RETRYABLE_ERRORS = frozenset({"TIMEOUT", "NETWORK", "CONNECT", "HTTP"})
_STATUS_RANK = {STATUS_FAILED: 0, STATUS_PARTIAL: 1, STATUS_OK: 2}


def _is_retryable(obs: Observation) -> bool:
    if obs.status == STATUS_FAILED:
        return obs.error_code in RETRYABLE_ERRORS
    return obs.status == STATUS_PARTIAL


def collect(target: Target, options: Options) -> Observation:
    """Probe the target, retrying transient network failures."""
    attempts = max(1, options.attempts)
    obs = _collect_once(target, options)
    used = 1
    if attempts == 1 or not _is_retryable(obs):
        return obs

    for used in range(2, attempts + 1):
        candidate = _collect_once(target, options)
        if _STATUS_RANK[candidate.status] >= _STATUS_RANK[obs.status]:
            obs = candidate
        if obs.status == STATUS_OK:
            break

    if obs.status == STATUS_OK:
        obs.notes.append(
            "связь нестабильна: успешный ответ получен с попытки %d из %d"
            % (used, attempts)
        )
    elif obs.status == STATUS_PARTIAL:
        obs.notes.append(
            "связь нестабильна: успех только частичный после %d попыток" % used
        )
    else:
        obs.notes.append("сервер не ответил за %d попыток" % used)
    return obs


def _collect_once(target: Target, options: Options) -> Observation:
    obs = Observation(
        target=target.url,
        host=target.host,
        port=target.port,
        scheme=target.scheme,
    )

    # Resolve first: without DNS there is nothing to check, and pretending
    # otherwise produced misleading "MITIGATED" verdicts.
    resolve_error = resolve_preflight(target.host, target.port)
    if resolve_error:
        obs.status = STATUS_FAILED
        obs.error_code, obs.error_message = resolve_error
        obs.notes.append(obs.error_message)
        return obs

    if target.scheme == "https":
        tls = probe_tls(target.host, target.port, options.timeout, options.verify)
        obs.tls_ok = tls.ok
        obs.tls_error = tls.error
        obs.tls_version = tls.version
        obs.alpn = tls.alpn
        obs.cert_verified = tls.cert_verified
        obs.h2_negotiated = tls.alpn == "h2" if tls.ok else None
        if not tls.ok:
            obs.status = STATUS_FAILED
            obs.error_code = tls.error_code
            obs.error_message = tls.error
            obs.notes.append("TLS: %s" % tls.error)
            return obs
    else:
        obs.notes.append("plain HTTP: HTTP/2 over TLS не проверяется")
        obs.h2_negotiated = False

    http = fingerprint(
        target.host, target.port, options.timeout, target.authority, target.path, options.verify
    )
    if http.ok:
        obs.http_status = http.status
        obs.headers = http.headers
        obs.server_header = http.headers.get("server")
        obs.cdn = detect_cdn(http.headers)
        obs.h3_altsvc = parse_altsvc(http.headers)

        version = parse_version(obs.server_header or "")
        source = obs.server_header or ""
        if version is None and http.body:
            text = http.body.decode("latin-1", "replace")
            version = parse_version(text)
            source = text
        if version is not None:
            obs.nginx_version = version
            match = _NGINX_VERSION_RE.search(source)
            obs.nginx_version_raw = match.group(0) if match else format_version(version)
            obs.distro = detect_distro(obs.server_header or "")
            if match and not re.match(
                r"(?i)^nginx/", obs.nginx_version_raw
            ):
                obs.notes.append(
                    "версия взята из токена «%s» (сборка с патчами); "
                    "при сомнении проверьте nginx -v на хосте"
                    % obs.nginx_version_raw
                )

        if obs.server_header:
            obs.server_is_nginx = is_nginx_family(obs.server_header)
            if "openresty" in obs.server_header.lower() and obs.nginx_version is None:
                obs.notes.append(
                    "OpenResty скрывает версию ядра nginx; статус патча "
                    "проверяется на хосте (openresty -v)"
                )
        elif http.body:
            obs.server_is_nginx = is_nginx_family(
                http.body.decode("latin-1", "replace")
            )
        if obs.server_is_nginx is False and obs.cdn is None:
            obs.notes.append(
                "Server: %s — не nginx; уязвимости неприменимы"
                % (obs.server_header or "?")
            )
    else:
        obs.error_code = http.error_code
        obs.error_message = http.error
        obs.notes.append("HTTP-запрос не удался: %s" % http.error)
        if target.scheme == "http":
            obs.status = STATUS_FAILED
            return obs
        obs.status = STATUS_PARTIAL

    if target.scheme == "https" and obs.h2_negotiated and options.h2_request:
        h2 = probe_h2(
            target.host, target.port, options.timeout, target.authority, options.verify
        )
        obs.h2_functional = h2.ok
        obs.h2_detail = h2.error if not h2.ok else "SETTINGS + ответ на HEADERS"
    elif target.scheme == "https" and obs.h2_negotiated:
        obs.h2_detail = "запрос отключён (--no-h2-request)"

    if target.scheme == "https" and options.h3:
        obs.h3_checked = True
        quic = probe_quic(target.host, target.port, options.timeout)
        obs.h3_quic = quic.detected
        obs.h3_udp_timeout = quic.timed_out
        obs.h3_detail = quic.error

    return obs


# --------------------------------------------------------------------------
# Verdict engine
# --------------------------------------------------------------------------


def _reason_prefix(obs: Observation) -> str:
    if obs.distro:
        return (
            "дистрибутивная сборка (%s): возможен бэкпорт исправления, "
            "сверьтесь с USN/пакетом" % obs.distro
        )
    return ""


def _version_part(obs: Observation, meta: Dict[str, Any]) -> Optional[str]:
    version = obs.nginx_version
    if version is None:
        return None
    return patch_status(version, meta["min_affected"])


def verdict_for(obs: Observation, meta: Dict[str, Any]) -> Tuple[str, str]:
    cve = meta["cve"]
    version = obs.nginx_version

    if obs.server_is_nginx is False and obs.cdn is None:
        return (
            NOT_APPLICABLE,
            "Server: %s — это не nginx" % (obs.server_header or "неизвестно"),
        )

    status = _version_part(obs, meta)

    if status == PATCHED:
        return (
            PATCHED,
            "nginx %s исправлен (1.31.9+ / 1.30.7+)" % format_version(version),
        )

    if status == NOT_AFFECTED:
        return (
            NOT_AFFECTED,
            "nginx %s старше первой уязвимой версии %s"
            % (format_version(version), format_version(meta["min_affected"])),
        )

    if status == "UNKNOWN":
        return (
            UNKNOWN,
            "версия %s вне известной таблицы; проверьте advisory вручную"
            % format_version(version),
        )

    if meta["needs"] == "mail":
        return (
            UNKNOWN,
            "mail proxy (proxy + auth_http) снаружи не определяется; "
            "проверьте конфигурацию на хосте",
        )

    if meta["needs"] == "resolver":
        if status == "VULNERABLE" and obs.distro:
            return (
                INCONCLUSIVE,
                _reason_prefix(obs) + "; нужен resolver + proxy_pass с переменной + mirror",
            )
        if status == "VULNERABLE":
            return (
                UNKNOWN,
                "nginx %s в уязвимом диапазоне, но нужен resolver + proxy_pass "
                "с переменной + mirror; снаружи не определить" % format_version(version),
            )
        return (
            UNKNOWN,
            "версия не определена; уязвимость зависит от конфигурации",
        )

    if obs.cdn:
        return (
            INCONCLUSIVE,
            "перед сервером CDN/прокси (%s); проверка бьёт в edge, а не в nginx. "
            "Запустите проверку против origin напрямую" % obs.cdn,
        )

    if meta["needs"] == "h2":
        if obs.scheme != "https":
            return (
                INCONCLUSIVE,
                "цель по HTTP: HTTP/2 (h2c) этим чекером не проверяется",
            )
        if obs.tls_ok is False:
            return (
                INCONCLUSIVE,
                "нет доступного TLS: %s" % (obs.tls_error or "не проверялось"),
            )
        if obs.h2_negotiated is False:
            return (
                MITIGATED,
                "HTTP/2 не согласован (ALPN=%s) — этот путь атаки отключён"
                % (obs.alpn or "http/1.1"),
            )
        if obs.h2_functional is False:
            return (
                INCONCLUSIVE,
                "ALPN=h2, но HTTP/2-обмен не удался: %s" % (obs.h2_detail or "?"),
            )
        if status == "VULNERABLE":
            if obs.distro:
                return (
                    INCONCLUSIVE,
                    _reason_prefix(obs) + "; HTTP/2 включён",
                )
            suffix = (
                "; требуется проксирование на upstream (типично для reverse proxy)"
                if cve == "CVE-2026-123633"
                else ""
            )
            return (
                LIKELY_VULNERABLE,
                "nginx %s попадает в уязвимый диапазон %s–%s, HTTP/2 согласован%s"
                % (
                    format_version(version),
                    format_version(meta["min_affected"]),
                    format_version(LAST_VULNERABLE),
                    suffix,
                ),
            )
        return (
            LIKELY_VULNERABLE,
            "версия скрыта, но HTTP/2 включён; исправленные релизы 1.31.9/1.30.7 "
            "вышли 18.11.2026 — считайте непропатченным, пока не доказано обратное",
        )

    if meta["needs"] == "h3":
        if obs.scheme != "https":
            return (NOT_AFFECTED, "HTTP/3 поверх TLS не используется")
        h3_seen = bool(obs.h3_altsvc or obs.h3_quic)
        if not h3_seen:
            if not obs.h3_checked:
                return (
                    UNKNOWN,
                    "проверка HTTP/3 отключена (--no-h3); в заголовках Alt-Svc нет",
                )
            if obs.h3_udp_timeout:
                return (
                    UNKNOWN,
                    "Alt-Svc нет, а UDP/443 не ответил (возможен фильтр) — "
                    "HTTP/3 снаружи не подтверждён; проверьте конфигурацию на хосте",
                )
            if obs.h3_quic is None:
                return (
                    INCONCLUSIVE,
                    "HTTP/3 не обнаружен, но QUIC-проба не удалась: %s"
                    % (obs.h3_detail or "нет данных"),
                )
            return (
                MITIGATED,
                "признаков HTTP/3 нет (Alt-Svc отсутствует, QUIC не ответил) — "
                "этот путь атаки не обнаружен",
            )
        if status == "VULNERABLE":
            if obs.distro:
                return (
                    INCONCLUSIVE,
                    _reason_prefix(obs) + "; HTTP/3 обнаружен",
                )
            return (
                LIKELY_VULNERABLE,
                "nginx %s в диапазоне 1.25.0–%s, HTTP/3 обнаружен"
                % (format_version(version), format_version(LAST_VULNERABLE)),
            )
        return (
            LIKELY_VULNERABLE,
            "версия скрыта, но HTTP/3 обнаружен; фикс только в 1.31.9+/1.30.7+",
        )

    return (UNKNOWN, "нет правила для %s" % cve)


def evaluate(obs: Observation) -> List[Finding]:
    findings = []
    for meta in CVE_META:
        verdict, reason = verdict_for(obs, meta)
        action, action_label = ACTION_BY_VERDICT.get(
            verdict, ("MANUAL", "проверить вручную")
        )
        findings.append(
            Finding(
                cve=meta["cve"],
                title=meta["title"],
                severity=meta["severity"],
                verdict=verdict,
                reason=reason,
                reference=meta["f5"],
                verdict_label=VERDICT_LABELS.get(verdict, verdict),
                action=action,
                action_label=action_label,
            )
        )
    return findings


def summarize(findings: Iterable[Finding], status: str = STATUS_OK) -> Dict[str, Any]:
    findings = list(findings)
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1

    if status == STATUS_FAILED:
        return {
            "verdict": "FAILED",
            "headline": "ПРОВЕРКА НЕ ВЫПОЛНЕНА",
            "action": "CHECK_FAILED",
            "action_label": "повторить проверку с другой сети",
            "detail": "нет соединения с сервером",
            "exit_code": 2,
            "counts": {},
            "uncheckable": 0,
        }
    if counts.get(LIKELY_VULNERABLE):
        verdict = "RISK"
        headline = "ТРЕБУЕТСЯ ДЕЙСТВИЕ"
        action = "UPDATE"
        action_label = "обновить nginx до 1.31.9/1.30.7"
        detail = "как минимум один путь атаки открыт"
        exit_code = 1
    elif counts.get(INCONCLUSIVE):
        verdict = "INCONCLUSIVE"
        headline = "НУЖНА РУЧНАЯ ПРОВЕРКА"
        action = "MANUAL"
        action_label = "уточнить CDN/бэкпорт/ошибку связи"
        detail = "автоматический вердикт невозможен"
        exit_code = 2
    else:
        verdict = "OK"
        headline = "ДЕЙСТВИЙ НЕ ТРЕБУЕТСЯ"
        action = "NONE"
        action_label = "ничего не делать"
        detail = ""
        exit_code = 0
    return {
        "verdict": verdict,
        "headline": headline,
        "action": action,
        "action_label": action_label,
        "detail": detail,
        "exit_code": exit_code,
        "counts": counts,
        "uncheckable": counts.get(UNKNOWN, 0),
    }


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _paint(text: str, verdict: str, enabled: bool) -> str:
    if not enabled:
        return text
    return "%s%s\033[0m" % (VERDICT_COLORS.get(verdict, ""), text)


def _paint_summary(text: str, summary: Dict[str, Any], enabled: bool) -> str:
    if not enabled:
        return text
    return "%s%s\033[0m" % (SUMMARY_COLORS.get(summary["verdict"], ""), text)


def render_human(result: Dict[str, Any], color: bool = False) -> str:
    obs = result["observation"]
    summary = result["summary"]
    lines = []
    lines.append("== %s ==" % obs["target"])

    if summary["verdict"] == "FAILED":
        reason = obs.get("error_message") or "неизвестная ошибка"
        advice = FAILURE_ADVICE.get(
            obs.get("error_code") or "",
            "проверить доступность сервера и повторить проверку",
        )
        lines.append("  Проверка     НЕ ВЫПОЛНЕНА")
        lines.append("  Причина      %s" % reason)
        lines.append("  Что делать   %s" % advice)
        lines.append("")
        lines.append("  CVE не проверялись: нет соединения с сервером.")
        lines.append(
            "  %s"
            % _paint_summary(
                "ИТОГ: ПРОВЕРКА НЕ ВЫПОЛНЕНА — выводов об уязвимости сделать нельзя.",
                summary,
                color,
            )
        )
        return "\n".join(lines)

    status = obs.get("status") or STATUS_OK
    status_text = STATUS_LABELS.get(status, status)
    if status == STATUS_PARTIAL and obs.get("error_message"):
        status_text += " (%s)" % obs["error_message"]
    lines.append("  Проверка     %s" % status_text)

    tls_bits = []
    if obs["tls_ok"]:
        tls_bits.append(obs["tls_version"] or "TLS")
        tls_bits.append("ALPN=%s" % (obs["alpn"] or "нет"))
    elif obs["tls_error"]:
        tls_bits.append("ошибка: %s" % obs["tls_error"])
    lines.append("  TLS      %s" % ("; ".join(tls_bits) or "не проверялся"))

    if obs["h2_negotiated"] is None:
        h2_text = "не проверялся"
    elif not obs["h2_negotiated"]:
        h2_text = "не согласован"
    elif obs["h2_functional"]:
        h2_text = "согласован, отвечает"
    elif obs["h2_functional"] is False:
        h2_text = "согласован, обмен не удался (%s)" % (obs["h2_detail"] or "?")
    else:
        h2_text = "согласован"
    lines.append("  HTTP/2   %s" % h2_text)

    h3_bits = []
    if obs["h3_altsvc"]:
        h3_bits.append("Alt-Svc h3")
    if obs["h3_quic"]:
        h3_bits.append("QUIC отвечает")
    lines.append("  HTTP/3   %s" % (", ".join(h3_bits) or "не обнаружен"))

    server = obs["server_header"] or "не раскрыт"
    lines.append("  Server   %s" % server)
    lines.append("  CDN      %s" % (obs["cdn"] or "не обнаружен"))
    if obs["notes"]:
        for note in obs["notes"]:
            lines.append("  note     %s" % note)
    lines.append("")

    findings = result["findings"]
    width = max(len(f["cve"]) for f in findings)
    label_width = max(
        len(VERDICT_LABELS.get(f["verdict"], f["verdict"])) for f in findings
    )
    for finding in findings:
        label = VERDICT_LABELS.get(finding["verdict"], finding["verdict"])
        painted = _paint(label, finding["verdict"], color)
        tail = ""
        if finding.get("action_label"):
            tail = "  → %s" % finding["action_label"]
        lines.append(
            "  %-*s  %s%s %s%s"
            % (
                width,
                finding["cve"],
                painted,
                " " * (label_width - len(label) + 2),
                finding["reason"],
                tail,
            )
        )

    lines.append("")
    lines.append(
        "  Сводка: %s"
        % (
            ", ".join(
                "%s=%d" % (VERDICT_LABELS.get(k, k), v)
                for k, v in sorted(summary["counts"].items())
            )
            or "нет данных"
        )
    )
    headline = "ИТОГ: %s" % summary["headline"]
    if summary.get("detail"):
        headline += " — %s" % summary["detail"]
    lines.append("  %s" % _paint_summary(headline, summary, color))
    if summary["uncheckable"]:
        lines.append(
            "  %d CVE проверяются только на сервере — см. docs/server-check.md"
            % summary["uncheckable"]
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def check_target(raw: str, options: Options, verbose: bool = False) -> Dict[str, Any]:
    target = parse_target(raw, options.port, options.path)
    obs = collect(target, options)
    if obs.status == STATUS_FAILED:
        findings: List[Finding] = []
    else:
        findings = evaluate(obs)
    summary = summarize(findings, obs.status)
    if verbose:
        print(
            "[*] %s -> status=%s TLS=%s ALPN=%s h2=%s/%s version=%s cdn=%s"
            % (
                target.url,
                obs.status,
                obs.tls_version or ("err" if obs.tls_error else "-"),
                obs.alpn or "-",
                obs.h2_negotiated,
                obs.h2_functional,
                format_version(obs.nginx_version) if obs.nginx_version else "unknown",
                obs.cdn or "-",
            ),
            file=sys.stderr,
        )
    error = None
    if obs.error_code:
        error = {"code": obs.error_code, "message": obs.error_message}
    return {
        "target": target.url,
        "status": obs.status,
        "error": error,
        "observation": obs.as_json(),
        "findings": [f.as_json() for f in findings],
        "summary": summary,
    }


def run(args: argparse.Namespace) -> int:
    options = Options(
        timeout=args.timeout,
        verify=args.verify,
        h2_request=not args.no_h2_request,
        h3=not args.no_h3,
        port=args.port,
        path=args.path,
        attempts=args.attempts,
    )

    targets: List[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    targets.extend(args.targets)
    if not targets:
        targets.append("-")
    if "-" in targets:
        stdin_targets = []
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                stdin_targets.append(line)
        targets = [t for t in targets if t != "-"] + stdin_targets
    if not targets:
        print("нет целей для проверки", file=sys.stderr)
        return 2

    results: List[Dict[str, Any]] = []
    exit_code = 0

    def work(raw: str) -> Dict[str, Any]:
        try:
            return check_target(raw, options, verbose=args.verbose)
        except Exception as exc:  # noqa: BLE001
            return {
                "target": raw,
                "status": STATUS_FAILED,
                "error": {"code": "INTERNAL", "message": "%s: %s" % (type(exc).__name__, exc)},
                "observation": None,
                "findings": [],
                "summary": {
                    "verdict": "FAILED",
                    "headline": "ПРОВЕРКА НЕ ВЫПОЛНЕНА",
                    "action": "CHECK_FAILED",
                    "action_label": "повторить проверку",
                    "detail": "внутренняя ошибка",
                    "exit_code": 2,
                    "counts": {},
                    "uncheckable": 0,
                },
            }

    if args.concurrency > 1 and len(targets) > 1:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(args.concurrency, 8)
        ) as pool:
            results = list(pool.map(work, targets))
    else:
        results = [work(raw) for raw in targets]

    for result in results:
        code = result["summary"].get("exit_code", 0)
        if code == 1:
            exit_code = 1
        elif code == 2 and exit_code == 0:
            exit_code = 2

    if args.json:
        payload = {
            "checker": "nginx2root-check",
            "version": CHECKER_VERSION,
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "advisory": ADVISORY_URL,
            "results": results,
        }
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        for index, result in enumerate(results):
            if index:
                print()
            if result.get("observation") is None:
                message = (result.get("error") or {}).get("message") or "неизвестная ошибка"
                print("== %s ==\n  Проверка     НЕ ВЫПОЛНЕНА\n  Причина      %s"
                      % (result["target"], message))
            else:
                print(render_human(result, color=color))

    return exit_code


class ArgumentParser(argparse.ArgumentParser):
    """argparse with a distinct exit code for usage errors (3, not 2)."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(3, "%s: error: %s\n" % (self.prog, message))


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="nginx2root_check.py",
        description=(
            "Безопасная внешняя проверка подверженности nginx уязвимостям "
            "nginx2root (CVE-2026-123007, -123634, -123633, -121810, -113425)."
        ),
        epilog="Подробности и ограничения — в README.md.",
    )
    parser.add_argument("targets", nargs="*", metavar="URL",
                        help="адрес сайта, напр. https://example.com или example.com:8443")
    parser.add_argument("--file", metavar="PATH",
                        help="файл со списком адресов (по одному в строке)")
    parser.add_argument("--port", type=int, default=None,
                        help="переопределить порт для всех целей")
    parser.add_argument("--path", default=None,
                        help="путь для fingerprint-запроса (по умолчанию из URL)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="таймаут соединения/чтения в секундах (по умолчанию 5)")
    parser.add_argument("--attempts", type=int, default=3,
                        help="попыток при таймауте/сетевой ошибке (по умолчанию 3)")
    parser.add_argument("--json", action="store_true", help="вывод в JSON")
    parser.add_argument("--no-h2-request", action="store_true",
                        help="не отправлять HTTP/2-запрос, только ALPN")
    parser.add_argument("--no-h3", action="store_true",
                        help="не проверять HTTP/3 (Alt-Svc и QUIC)")
    parser.add_argument("--verify", action="store_true",
                        help="проверять TLS-сертификат (по умолчанию отключено)")
    parser.add_argument("--concurrency", type=int, default=2,
                        help="параллельных проверок в batch-режиме (по умолчанию 2)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="диагностический вывод в stderr")
    parser.add_argument("--version", action="version",
                        version="nginx2root-check %s" % CHECKER_VERSION)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.port is not None and not (1 <= args.port <= 65535):
        parser.error("--port должен быть в диапазоне 1..65535")
    if args.timeout <= 0:
        parser.error("--timeout должен быть больше нуля")
    if args.attempts < 1:
        parser.error("--attempts должен быть не меньше 1")
    if not args.targets and not args.file and sys.stdin.isatty():
        parser.error("укажите URL (или --file, или список в stdin)")
    try:
        return run(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
