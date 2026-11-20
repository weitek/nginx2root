#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for nginx2root_check.

Run with:  python3 -m unittest discover -s tests -v

No third-party packages are required. The network tests start local TLS/UDP
servers in background threads and do not touch the Internet.
"""

import contextlib
import io
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nginx2root_check as chk  # noqa: E402

CERT = None
KEY = None


def setUpModule():
    global CERT, KEY
    tmp = tempfile.mkdtemp(prefix="nginx2root-test-")
    CERT = os.path.join(tmp, "cert.pem")
    KEY = os.path.join(tmp, "key.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", KEY, "-out", CERT, "-days", "2",
            "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )


# --------------------------------------------------------------------------
# Version / verdict unit tests
# --------------------------------------------------------------------------


class VersionTests(unittest.TestCase):
    def test_parse_server_header(self):
        self.assertEqual(chk.parse_version("nginx/1.24.0"), (1, 24, 0))
        self.assertEqual(chk.parse_version("nginx/1.24.0 (Ubuntu)"), (1, 24, 0))
        self.assertEqual(chk.parse_version("1.31.9"), None)
        self.assertIsNone(chk.parse_version("cloudflare"))

    def test_parse_custom_product_tokens(self):
        self.assertEqual(chk.parse_version("nginx-reuseport/1.30.7"), (1, 30, 7))
        self.assertEqual(chk.parse_version("nginx-naxsi/1.24.0"), (1, 24, 0))
        self.assertEqual(chk.parse_version("nginx-extras/1.18.0"), (1, 18, 0))
        self.assertEqual(chk.parse_version("Nginx_Plus/1.25.5"), (1, 25, 5))
        # Other products keep their own versioning and must not be parsed.
        self.assertIsNone(chk.parse_version("openresty/1.25.3.2"))
        self.assertIsNone(chk.parse_version("Tengine/2.3.3"))

    def test_parse_version_from_body(self):
        body = "<html><hr><center>nginx/1.31.8</center></html>"
        self.assertEqual(chk.parse_version(body), (1, 31, 8))

    def test_patch_status(self):
        cases = [
            ((1, 9, 4), (1, 9, 5), chk.NOT_AFFECTED),
            ((1, 9, 5), (1, 9, 5), "VULNERABLE"),
            ((1, 18, 0), (1, 9, 5), "VULNERABLE"),
            ((1, 24, 0), (1, 19, 7), "VULNERABLE"),
            ((1, 30, 6), (1, 9, 5), "VULNERABLE"),
            ((1, 30, 7), (1, 9, 5), chk.PATCHED),
            ((1, 31, 8), (1, 9, 5), "VULNERABLE"),
            ((1, 31, 9), (1, 9, 5), chk.PATCHED),
            ((1, 31, 9), (1, 19, 7), chk.PATCHED),
            ((1, 20, 0), (1, 25, 0), chk.NOT_AFFECTED),
            ((1, 25, 0), (1, 25, 0), "VULNERABLE"),
            ((0, 5, 32), (0, 5, 33), chk.NOT_AFFECTED),
            ((0, 5, 33), (0, 5, 33), "VULNERABLE"),
            ((2, 0, 0), (1, 9, 5), chk.PATCHED),
        ]
        for version, minimum, expected in cases:
            with self.subTest(version=version, minimum=minimum):
                self.assertEqual(chk.patch_status(version, minimum), expected)

    def test_distro_detection(self):
        self.assertEqual(chk.detect_distro("nginx/1.18.0 (Ubuntu)"), "Ubuntu")
        self.assertEqual(
            chk.detect_distro("nginx/1.22.1 (Debian)"), "Debian"
        )
        self.assertIsNone(chk.detect_distro("nginx/1.31.8"))


class AdvisoryTests(unittest.TestCase):
    def test_advisory_metadata(self):
        self.assertEqual(chk.CVE_META[0]["severity"], "major")
        self.assertEqual(chk.CVE_META[-1]["min_affected"], (0, 5, 33))


class TlsContextTests(unittest.TestCase):
    def test_verify_enables_certificate_and_hostname_checks(self):
        context = chk.make_tls_context(("h2", "http/1.1"), verify=True)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_no_verify_disables_certificate_and_hostname_checks(self):
        context = chk.make_tls_context(("http/1.1",), verify=False)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)


class HpackTests(unittest.TestCase):
    def test_request_headers(self):
        expected = (
            b"\x82\x87\x84"
            b"\x01\x0bexample.com"
            + chk._encode_int(58, 4, 0x00)
            + chk._encode_str(chk.USER_AGENT)
        )
        self.assertEqual(chk.hpack_request_headers("example.com"), expected)

    def test_frame_layout(self):
        frame = chk.h2_frame(chk.H2_FRAME_SETTINGS, 0, 0)
        self.assertEqual(frame, b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")

    def test_frame_has_length_type_and_stream(self):
        frame = chk.h2_frame(chk.H2_FRAME_HEADERS, 0x5, 1, b"\x88")
        self.assertEqual(frame[:3], b"\x00\x00\x01")
        self.assertEqual(frame[3], chk.H2_FRAME_HEADERS)
        self.assertEqual(frame[4], 0x5)
        self.assertEqual(struct.unpack(">I", frame[5:9])[0], 1)
        self.assertEqual(frame[9:], b"\x88")


class QuicTests(unittest.TestCase):
    def test_packet_shape(self):
        packet, scid = chk.build_quic_vn_probe()
        self.assertEqual(len(packet), 1200)
        self.assertEqual(packet[0], 0xC0)
        self.assertEqual(
            struct.unpack(">I", packet[1:5])[0], chk.QUIC_UNSUPPORTED_VERSION
        )
        dcid_len = packet[5]
        scid_len = packet[6 + dcid_len]
        self.assertEqual(packet[7 + dcid_len : 7 + dcid_len + scid_len], scid)
        self.assertEqual(len(scid), 8)

    def test_version_negotiation_matching(self):
        scid = b"ABCDEFGH"
        packet = b"\x80\x00\x00\x00\x00" + bytes((len(scid),)) + scid
        self.assertTrue(chk.is_version_negotiation(packet, scid))
        self.assertFalse(chk.is_version_negotiation(packet, b"ZZZZZZZZ"))
        self.assertFalse(chk.is_version_negotiation(b"\x80\x00\x00\x00\x01", scid))
        self.assertFalse(chk.is_version_negotiation(b"short", scid))

    def test_altsvc_parsing(self):
        self.assertTrue(chk.parse_altsvc({"alt-svc": 'h3=":443"; ma=86400'}))
        self.assertTrue(chk.parse_altsvc({"alt-svc": 'h3-29=":443", h3=":443"'}))
        self.assertFalse(chk.parse_altsvc({}))
        self.assertFalse(chk.parse_altsvc({"alt-svc": 'h2=":443"'}))


# --------------------------------------------------------------------------
# Verdict engine with fabricated observations
# --------------------------------------------------------------------------


def make_obs(**kwargs):
    base = dict(
        target="https://example.com",
        host="example.com",
        port=443,
        scheme="https",
        tls_ok=True,
        alpn="h2",
        h2_negotiated=True,
        h2_functional=True,
        nginx_version=(1, 31, 8),
        server_header="nginx/1.31.8",
        server_is_nginx=True,
        h3_checked=True,
        h3_quic=False,
    )
    base.update(kwargs)
    return chk.Observation(**base)


def verdict_for(obs, cve):
    for finding in chk.evaluate(obs):
        if finding.cve == cve:
            return finding.verdict
    raise AssertionError("no finding for %s" % cve)


class VerdictTests(unittest.TestCase):
    def test_h2_and_vulnerable_version(self):
        obs = make_obs()
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.LIKELY_VULNERABLE
        )
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123633"), chk.LIKELY_VULNERABLE
        )

    def test_h2_disabled_mitigates(self):
        obs = make_obs(alpn="http/1.1", h2_negotiated=False, h2_functional=None)
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.MITIGATED)
        self.assertEqual(verdict_for(obs, "CVE-2026-123633"), chk.MITIGATED)

    def test_patched_version(self):
        obs = make_obs(nginx_version=(1, 31, 9), server_header="nginx/1.31.9")
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.PATCHED)
        self.assertEqual(verdict_for(obs, "CVE-2026-123634"), chk.PATCHED)
        self.assertEqual(verdict_for(obs, "CVE-2026-113425"), chk.PATCHED)

    def test_stable_branch_boundary(self):
        obs = make_obs(nginx_version=(1, 30, 7), server_header="nginx/1.30.7")
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.PATCHED)
        obs = make_obs(nginx_version=(1, 30, 6), server_header="nginx/1.30.6")
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.LIKELY_VULNERABLE
        )

    def test_custom_token_patched(self):
        obs = make_obs(
            nginx_version=(1, 30, 7),
            server_header="nginx-reuseport/1.30.7",
            nginx_version_raw="nginx-reuseport/1.30.7",
        )
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.PATCHED)
        self.assertEqual(verdict_for(obs, "CVE-2026-123633"), chk.PATCHED)

    def test_old_version_not_affected(self):
        obs = make_obs(nginx_version=(1, 9, 4), server_header="nginx/1.9.4")
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.NOT_AFFECTED)

    def test_unknown_version_with_h2(self):
        obs = make_obs(nginx_version=None, server_header="nginx")
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.LIKELY_VULNERABLE
        )

    def test_distro_backport_is_inconclusive(self):
        obs = make_obs(
            nginx_version=(1, 24, 0),
            server_header="nginx/1.24.0 (Ubuntu)",
            distro="Ubuntu",
        )
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.INCONCLUSIVE
        )

    def test_cdn_is_inconclusive(self):
        obs = make_obs(cdn="Cloudflare", server_header="cloudflare")
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.INCONCLUSIVE)

    def test_cdn_patched_edge_version_does_not_describe_origin(self):
        obs = make_obs(
            cdn="Cloudflare",
            nginx_version=(1, 31, 9),
            server_header="nginx/1.31.9",
        )
        for finding in chk.evaluate(obs):
            with self.subTest(cve=finding.cve):
                self.assertEqual(finding.verdict, chk.INCONCLUSIVE)

    def test_other_server_is_not_applicable(self):
        obs = make_obs(
            server_header="Apache/2.4.62", server_is_nginx=False,
            nginx_version=None,
        )
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.NOT_APPLICABLE
        )

    def test_openresty_is_nginx_family(self):
        self.assertTrue(chk.is_nginx_family("openresty"))
        self.assertTrue(chk.is_nginx_family("nginx/1.31.8"))
        self.assertTrue(chk.is_nginx_family("Tengine"))
        self.assertFalse(chk.is_nginx_family("Apache/2.4"))
        obs = make_obs(server_header="openresty", nginx_version=None)
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.LIKELY_VULNERABLE
        )
        obs = make_obs(
            server_header="openresty", nginx_version=None,
            alpn="http/1.1", h2_negotiated=False, h2_functional=None,
        )
        self.assertEqual(verdict_for(obs, "CVE-2026-123007"), chk.MITIGATED)

    def test_config_only_cves_are_unknown(self):
        obs = make_obs()
        self.assertEqual(verdict_for(obs, "CVE-2026-123634"), chk.UNKNOWN)
        self.assertEqual(verdict_for(obs, "CVE-2026-113425"), chk.UNKNOWN)

    def test_http3_detected(self):
        obs = make_obs(h3_altsvc=True, h3_quic=True)
        self.assertEqual(
            verdict_for(obs, "CVE-2026-121810"), chk.LIKELY_VULNERABLE
        )

    def test_http3_absent(self):
        obs = make_obs(h3_quic=False)
        self.assertEqual(verdict_for(obs, "CVE-2026-121810"), chk.MITIGATED)

    def test_http3_udp_timeout_is_unknown(self):
        obs = make_obs(h3_quic=False, h3_udp_timeout=True, h3_detail="UDP/443: нет ответа")
        self.assertEqual(verdict_for(obs, "CVE-2026-121810"), chk.UNKNOWN)

    def test_http3_probe_failed_is_inconclusive(self):
        obs = make_obs(h3_quic=None, h3_altsvc=False)
        self.assertEqual(
            verdict_for(obs, "CVE-2026-121810"), chk.INCONCLUSIVE
        )

    def test_http3_disabled_is_unknown(self):
        obs = make_obs(h3_quic=None, h3_altsvc=False, h3_checked=False)
        self.assertEqual(
            verdict_for(obs, "CVE-2026-121810"), chk.UNKNOWN
        )

    def test_http3_below_minimum(self):
        obs = make_obs(
            nginx_version=(1, 24, 0), server_header="nginx/1.24.0",
            h3_altsvc=True,
        )
        self.assertEqual(
            verdict_for(obs, "CVE-2026-121810"), chk.NOT_AFFECTED
        )

    def test_tls_failure_is_inconclusive(self):
        obs = make_obs(
            tls_ok=False, tls_error="refused", alpn=None,
            h2_negotiated=None, h2_functional=None,
        )
        self.assertEqual(
            verdict_for(obs, "CVE-2026-123007"), chk.INCONCLUSIVE
        )


class SummaryTests(unittest.TestCase):
    def test_risk(self):
        findings = [chk.Finding("CVE-X", "t", "critical", chk.LIKELY_VULNERABLE, "r", "u")]
        summary = chk.summarize(findings)
        self.assertEqual(summary["verdict"], "RISK")
        self.assertEqual(summary["exit_code"], 1)
        self.assertEqual(summary["headline"], "ТРЕБУЕТСЯ ДЕЙСТВИЕ")
        self.assertEqual(summary["action"], "UPDATE")

    def test_inconclusive(self):
        findings = [chk.Finding("CVE-X", "t", "medium", chk.INCONCLUSIVE, "r", "u")]
        summary = chk.summarize(findings)
        self.assertEqual(summary["verdict"], "INCONCLUSIVE")
        self.assertEqual(summary["exit_code"], 2)
        self.assertEqual(summary["headline"], "НУЖНА РУЧНАЯ ПРОВЕРКА")

    def test_ok(self):
        findings = [
            chk.Finding("CVE-X", "t", "medium", chk.PATCHED, "r", "u"),
            chk.Finding("CVE-Y", "t", "medium", chk.MITIGATED, "r", "u"),
        ]
        summary = chk.summarize(findings)
        self.assertEqual(summary["verdict"], "OK")
        self.assertEqual(summary["exit_code"], 0)
        self.assertEqual(summary["headline"], "ДЕЙСТВИЙ НЕ ТРЕБУЕТСЯ")
        self.assertEqual(summary["uncheckable"], 0)

    def test_unknown_requires_host_check(self):
        findings = [
            chk.Finding("CVE-X", "t", "medium", chk.PATCHED, "r", "u"),
            chk.Finding("CVE-Y", "t", "medium", chk.UNKNOWN, "r", "u"),
        ]
        summary = chk.summarize(findings)
        self.assertEqual(summary["verdict"], "INCONCLUSIVE")
        self.assertEqual(summary["exit_code"], 2)
        self.assertEqual(summary["headline"], "НУЖНА ПРОВЕРКА НА СЕРВЕРЕ")
        self.assertEqual(summary["action"], "CHECK_HOST")
        self.assertEqual(summary["uncheckable"], 1)

    def test_failed(self):
        summary = chk.summarize([], chk.STATUS_FAILED)
        self.assertEqual(summary["verdict"], "FAILED")
        self.assertEqual(summary["exit_code"], 2)
        self.assertEqual(summary["headline"], "ПРОВЕРКА НЕ ВЫПОЛНЕНА")

    def test_verdict_labels_and_actions(self):
        obs = make_obs()
        findings = {f.cve: f for f in chk.evaluate(obs)}
        critical = findings["CVE-2026-123007"]
        self.assertEqual(critical.verdict_label, "ВЕРОЯТНО УЯЗВИМ")
        self.assertEqual(critical.action, "UPDATE")
        self.assertIn("обновить nginx", critical.action_label)
        config_only = findings["CVE-2026-123634"]
        self.assertEqual(config_only.verdict_label, "ПРОВЕРИТЬ НА СЕРВЕРЕ")
        self.assertEqual(config_only.action, "CHECK_HOST")


# --------------------------------------------------------------------------
# Local servers
# --------------------------------------------------------------------------


class FakeNginx:
    """Tiny TCP/TLS server that speaks just enough HTTP/1.1 and HTTP/2."""

    def __init__(self, server_header="nginx/1.31.8", alpn=("h2", "http/1.1"),
                 extra_headers=None, use_tls=True):
        self.server_header = server_header
        self.extra_headers = extra_headers or []
        self.alpn = list(alpn)
        self.use_tls = use_tls
        self._stop = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.context = None
        if self.use_tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(CERT, KEY)
            self.context.set_alpn_protocols(self.alpn)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.settimeout(3)
        try:
            tls = (
                self.context.wrap_socket(conn, server_side=True)
                if self.use_tls else conn
            )
        except Exception:  # noqa: BLE001 - handshake failures are expected in tests
            conn.close()
            return
        with tls:
            try:
                data = b""
                while len(data) < 24:
                    chunk = tls.recv(24 - len(data))
                    if not chunk:
                        return
                    data += chunk
                if data.startswith(b"PRI * HTTP/2.0"):
                    self._handle_h2(tls)
                else:
                    self._handle_h1(tls, data)
            except Exception:  # noqa: BLE001
                pass

    def _handle_h1(self, tls, data):
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        body = b"<html><body>not found</body></html>"
        lines = [
            "HTTP/1.1 200 OK",
            "Server: %s" % self.server_header,
            "Content-Type: text/html",
            "Content-Length: %d" % len(body),
            "Connection: close",
        ]
        lines.extend(self.extra_headers)
        response = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        tls.sendall(response)

    def _handle_h2(self, tls):
        tls.sendall(chk.h2_frame(chk.H2_FRAME_SETTINGS, 0, 0))
        for _ in range(8):
            header = chk._recv_exact(tls, 9)
            length = int.from_bytes(header[:3], "big")
            frame_type = header[3]
            if length:
                chk._recv_exact(tls, length)
            if frame_type == chk.H2_FRAME_HEADERS:
                break
            if frame_type == chk.H2_FRAME_GOAWAY:
                return
        tls.sendall(
            chk.h2_frame(
                chk.H2_FRAME_HEADERS,
                chk.H2_FLAG_END_STREAM | chk.H2_FLAG_END_HEADERS,
                1,
                b"\x88",  # indexed :status 200
            )
        )


class FakeQuic:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            if len(data) < 8:
                continue
            dcid_len = data[5]
            dcid = data[6 : 6 + dcid_len]
            scid_len = data[6 + dcid_len]
            scid = data[7 + dcid_len : 7 + dcid_len + scid_len]
            response = (
                b"\x80\x00\x00\x00\x00"
                + bytes((len(scid),)) + scid
                + bytes((len(dcid),)) + dcid
            )
            self.sock.sendto(response, addr)


class NetworkTests(unittest.TestCase):
    def test_plain_http(self):
        server = FakeNginx(use_tls=False)
        try:
            target = chk.parse_target("http://127.0.0.1:%d/" % server.port, None, None)
            obs = chk.collect(target, chk.Options(timeout=2, h3=False))
        finally:
            server.close()
        self.assertEqual(obs.status, chk.STATUS_OK)
        self.assertFalse(obs.tls_ok)
        self.assertEqual(obs.http_status, 200)
        self.assertEqual(obs.nginx_version, (1, 31, 8))
        findings = {f.cve: f.verdict for f in chk.evaluate(obs)}
        self.assertEqual(findings["CVE-2026-123007"], chk.INCONCLUSIVE)

    def test_http1_only(self):
        server = FakeNginx(alpn=("http/1.1",))
        try:
            target = chk.parse_target("https://127.0.0.1:%d/" % server.port, None, None)
            obs = chk.collect(target, chk.Options(timeout=2, h3=False))
        finally:
            server.close()
        self.assertTrue(obs.tls_ok)
        self.assertEqual(obs.alpn, "http/1.1")
        self.assertFalse(obs.h2_negotiated)
        self.assertEqual(obs.nginx_version, (1, 31, 8))
        findings = {f.cve: f.verdict for f in chk.evaluate(obs)}
        self.assertEqual(findings["CVE-2026-123007"], chk.MITIGATED)

    def test_http2_vulnerable(self):
        server = FakeNginx(server_header="nginx/1.31.8")
        try:
            target = chk.parse_target("https://127.0.0.1:%d/" % server.port, None, None)
            obs = chk.collect(target, chk.Options(timeout=2, h3=False))
        finally:
            server.close()
        self.assertEqual(obs.alpn, "h2")
        self.assertTrue(obs.h2_negotiated)
        self.assertTrue(obs.h2_functional, obs.h2_detail)
        findings = {f.cve: f.verdict for f in chk.evaluate(obs)}
        self.assertEqual(findings["CVE-2026-123007"], chk.LIKELY_VULNERABLE)

    def test_http2_patched(self):
        server = FakeNginx(server_header="nginx/1.31.9")
        try:
            target = chk.parse_target("https://127.0.0.1:%d/" % server.port, None, None)
            obs = chk.collect(target, chk.Options(timeout=2, h3=False))
        finally:
            server.close()
        findings = {f.cve: f.verdict for f in chk.evaluate(obs)}
        self.assertEqual(findings["CVE-2026-123007"], chk.PATCHED)

    def test_cdn_header(self):
        server = FakeNginx(
            server_header="cloudflare",
            extra_headers=["CF-Ray: 1234567890-LHR"],
        )
        try:
            target = chk.parse_target("https://127.0.0.1:%d/" % server.port, None, None)
            obs = chk.collect(target, chk.Options(timeout=2, h3=False))
        finally:
            server.close()
        self.assertEqual(obs.cdn, "Cloudflare")
        findings = {f.cve: f.verdict for f in chk.evaluate(obs)}
        self.assertEqual(findings["CVE-2026-123007"], chk.INCONCLUSIVE)

    def test_quic_detection(self):
        server = FakeQuic()
        try:
            result = chk.probe_quic("127.0.0.1", server.port, 2)
        finally:
            server.close()
        self.assertTrue(result.detected, result.error)

    def test_quic_closed_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        result = chk.probe_quic("127.0.0.1", port, 0.5)
        self.assertFalse(result.detected)


class RetryTests(unittest.TestCase):
    """collect() retries only transient network failures."""

    def _obs(self, status, code=None):
        obs = make_obs(status=status)
        obs.error_code = code
        obs.error_message = "моделированная ошибка"
        return obs

    def _patch(self, results):
        calls = []

        def fake(target, options):
            calls.append(1)
            return results.pop(0)

        original = chk._collect_once
        chk._collect_once = fake
        self.addCleanup(setattr, chk, "_collect_once", original)
        return calls

    def test_retries_timeout_and_reports(self):
        results = [
            self._obs(chk.STATUS_FAILED, "TIMEOUT"),
            self._obs(chk.STATUS_OK),
        ]
        calls = self._patch(results)
        obs = chk.collect(
            chk.parse_target("https://example.com", None, None),
            chk.Options(attempts=3),
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(obs.status, chk.STATUS_OK)
        self.assertTrue(any("нестабильна" in n for n in obs.notes))

    def test_stops_when_attempts_exhausted(self):
        results = [
            self._obs(chk.STATUS_FAILED, "TIMEOUT"),
            self._obs(chk.STATUS_FAILED, "TIMEOUT"),
            self._obs(chk.STATUS_FAILED, "TIMEOUT"),
        ]
        calls = self._patch(results)
        obs = chk.collect(
            chk.parse_target("https://example.com", None, None),
            chk.Options(attempts=3),
        )
        self.assertEqual(len(calls), 3)
        self.assertEqual(obs.status, chk.STATUS_FAILED)
        self.assertTrue(any("3 попыток" in n for n in obs.notes))

    def test_no_retry_for_dns_or_tls_errors(self):
        for code in ("DNS", "TLS_CERT"):
            results = [self._obs(chk.STATUS_FAILED, code)]
            calls = self._patch(results)
            obs = chk.collect(
                chk.parse_target("https://example.com", None, None),
            chk.Options(attempts=3),
            )
            self.assertEqual(len(calls), 1)
            self.assertEqual(obs.status, chk.STATUS_FAILED)

    def test_partial_result_is_not_lost(self):
        results = [
            self._obs(chk.STATUS_PARTIAL, "TIMEOUT"),
            self._obs(chk.STATUS_FAILED, "TIMEOUT"),
        ]
        self._patch(results)
        obs = chk.collect(
            chk.parse_target("https://example.com", None, None),
            chk.Options(attempts=2),
        )
        self.assertEqual(obs.status, chk.STATUS_PARTIAL)


class FailureAndRenderingTests(unittest.TestCase):
    def test_dns_failure_short_circuits(self):
        url = "https://nonexistent-nginx2root-check.invalid/"
        result = chk.check_target(url, chk.Options(timeout=1, h3=False))
        self.assertEqual(result["status"], chk.STATUS_FAILED)
        self.assertEqual(result["error"]["code"], "DNS")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["exit_code"], 2)
        text = chk.render_human(result, color=False)
        self.assertIn("Проверка     НЕ ВЫПОЛНЕНА", text)
        self.assertIn("ИТОГ: ПРОВЕРКА НЕ ВЫПОЛНЕНА", text)
        self.assertNotIn("CVE-2026-123007", text)
        self.assertNotIn("gaierror", text)

    def test_render_has_actions_and_summary(self):
        obs = make_obs(h3_quic=False)
        findings = chk.evaluate(obs)
        result = {
            "target": obs.target,
            "status": obs.status,
            "error": None,
            "observation": obs.as_json(),
            "findings": [f.as_json() for f in findings],
            "summary": chk.summarize(findings, obs.status),
        }
        text = chk.render_human(result, color=False)
        self.assertIn("ИТОГ: ТРЕБУЕТСЯ ДЕЙСТВИЕ", text)
        self.assertIn("ВЕРОЯТНО УЯЗВИМ", text)
        self.assertIn("обновить nginx", text)
        self.assertIn("ПРОВЕРИТЬ НА СЕРВЕРЕ", text)


class CliTests(unittest.TestCase):
    def test_invalid_concurrency_is_usage_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            chk.main(["--concurrency", "0", "https://example.com"])
        self.assertEqual(raised.exception.code, 3)
        self.assertIn("--concurrency", stderr.getvalue())

    def test_missing_target_file_has_no_traceback(self):
        with tempfile.TemporaryDirectory(prefix="nginx2root-test-") as tmp:
            missing = os.path.join(tmp, "missing.txt")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = chk.main(["--file", missing])
        self.assertEqual(exit_code, 2)
        self.assertIn("ошибка ввода/вывода", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


class TargetParsingTests(unittest.TestCase):
    def test_variants(self):
        cases = [
            ("example.com", "https://example.com/", 443),
            ("https://example.com/path", "https://example.com/path", 443),
            ("http://example.com", "http://example.com/", 80),
            ("example.com:8443", "https://example.com:8443/", 8443),
            ("https://example.com:443/x", "https://example.com/x", 443),
        ]
        for raw, url, port in cases:
            with self.subTest(raw=raw):
                target = chk.parse_target(raw, None, None)
                self.assertEqual(target.url, url)
                self.assertEqual(target.port, port)

    def test_port_override(self):
        target = chk.parse_target("https://example.com", 8443, None)
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.url, "https://example.com:8443/")

    def test_invalid(self):
        with self.assertRaises(ValueError):
            chk.parse_target("ftp://example.com", None, None)
        with self.assertRaises(ValueError):
            chk.parse_target("", None, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
