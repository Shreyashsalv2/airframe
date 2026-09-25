"""Network probes — the measurements themselves.

Every probe returns a `ProbeResult` rather than raising, because **a failed
measurement is data**. "DNS to Airtel timed out" is a finding; an exception that
aborts the run loses the other nine endpoints and tells you nothing about them.

Each probe measures one layer, and the layering is the point — a slow page load
could be DNS, TCP setup, TLS negotiation, or the server itself, and only separate
measurements can say which:

    icmp_rtt      raw network round trip          (is the path slow?)
    dns           name resolution                 (is the resolver slow?)
    tcp_connect   three-way handshake             (is the path slow *and* lossy?)
    tls_handshake certificate exchange            (is crypto setup the cost?)
    http_ttfb     time to first byte              (is the server slow?)
    throughput    sustained bulk transfer         (is the pipe wide enough?)

`iperf3` is used for throughput when present; otherwise an HTTP bulk download
substitutes. Both are reported honestly with their method recorded, because an
HTTP-derived figure and an iperf3 figure are not the same measurement and should
never be silently mixed in one baseline.
"""

from __future__ import annotations

import http.client
import re
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from airframe.kpi.endpoints import Endpoint


@dataclass
class ProbeResult:
    endpoint: str
    host: str
    probe: str
    value: float | None
    unit: str
    ok: bool = True
    error: str | None = None
    method: str | None = None            # e.g. "iperf3" vs "http_range"
    extra: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        if not self.ok:
            return f"{self.endpoint:<18} {self.probe:<14} FAILED  ({self.error})"
        return (
            f"{self.endpoint:<18} {self.probe:<14} {self.value:8.2f} {self.unit}"
            + (f"  [{self.method}]" if self.method else "")
        )


def _now() -> float:
    """Monotonic clock. Never `time.time()` for durations — a clock adjustment
    (NTP step, DST, manual change) mid-measurement produces a negative latency."""
    return time.perf_counter()


# ---------------------------------------------------------------- ICMP


def probe_icmp(endpoint: Endpoint, count: int = 10, timeout_s: float = 5.0) -> list[ProbeResult]:
    """Ping. Returns rtt / loss / jitter as three results.

    Shells out to `ping` rather than opening a raw socket, because raw ICMP sockets
    require root on macOS. Requiring sudo for a basic latency measurement would make
    the whole KPI suite unusable in CI and annoying locally.
    """
    if not endpoint.host:
        return [ProbeResult(endpoint.name, "", "icmp_rtt", None, "ms", False, "no host")]

    cmd = ["ping", "-c", str(count), "-W", str(int(timeout_s * 1000)), endpoint.host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s * count + 10)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return [ProbeResult(endpoint.name, endpoint.host, "icmp_rtt", None, "ms",
                            False, f"ping failed: {exc}")]

    out = proc.stdout
    rtts = [float(m) for m in re.findall(r"time[=<]([\d.]+)\s*ms", out)]

    loss = 100.0
    m = re.search(r"([\d.]+)%\s*packet loss", out)
    if m:
        loss = float(m.group(1))
    elif rtts:
        loss = 100.0 * (count - len(rtts)) / count

    results: list[ProbeResult] = []
    if rtts:
        from airframe.kpi.stats import jitter_rfc3550, median

        results.append(ProbeResult(endpoint.name, endpoint.host, "icmp_rtt",
                                   median(rtts), "ms", True,
                                   extra={"samples": rtts, "count": len(rtts)}))
        results.append(ProbeResult(endpoint.name, endpoint.host, "jitter",
                                   jitter_rfc3550(rtts), "ms", True))
    else:
        results.append(ProbeResult(endpoint.name, endpoint.host, "icmp_rtt", None, "ms",
                                   False, "no replies (ICMP may be filtered)"))
    results.append(ProbeResult(endpoint.name, endpoint.host, "loss", loss, "pct",
                               ok=True))
    return results


# ---------------------------------------------------------------- DNS


def probe_dns(
    endpoint: Endpoint, query: str = "www.google.co.in", timeout_s: float = 5.0
) -> ProbeResult:
    """Time a real DNS query against this specific resolver.

    A hand-built query rather than `socket.getaddrinfo`, because getaddrinfo uses
    the *system* resolver and its cache — so it would measure the OS cache, not the
    endpoint, and the second measurement would always look instant.
    """
    if not endpoint.supports_dns:
        return ProbeResult(endpoint.name, endpoint.host, "dns", None, "ms", False,
                           "endpoint is not a resolver")

    # Minimal DNS query packet: header + QNAME + QTYPE(A) + QCLASS(IN)
    txid = b"\xab\xcd"
    header = txid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
    qname = b"".join(bytes([len(p)]) + p.encode() for p in query.split(".")) + b"\x00"
    packet = header + qname + b"\x00\x01\x00\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        start = _now()
        sock.sendto(packet, (endpoint.host, 53))
        data, _ = sock.recvfrom(4096)
        elapsed_ms = (_now() - start) * 1000.0

        if len(data) < 4 or data[:2] != txid:
            return ProbeResult(endpoint.name, endpoint.host, "dns", None, "ms", False,
                               "response transaction id did not match")
        rcode = data[3] & 0x0F
        if rcode != 0:
            return ProbeResult(endpoint.name, endpoint.host, "dns", elapsed_ms, "ms",
                               False, f"DNS rcode {rcode}")
        answers = int.from_bytes(data[6:8], "big")
        return ProbeResult(endpoint.name, endpoint.host, "dns", elapsed_ms, "ms", True,
                           extra={"answers": answers, "query": query})
    except TimeoutError:
        return ProbeResult(endpoint.name, endpoint.host, "dns", None, "ms", False,
                           f"timed out after {timeout_s}s")
    except OSError as exc:
        return ProbeResult(endpoint.name, endpoint.host, "dns", None, "ms", False, str(exc))
    finally:
        sock.close()


# ---------------------------------------------------------------- TCP / TLS


def probe_tcp_connect(endpoint: Endpoint, timeout_s: float = 5.0) -> ProbeResult:
    """Time the TCP three-way handshake.

    More informative than ping for user-facing latency: it traverses the same path
    but is also affected by SYN loss and by middleboxes, and unlike ICMP it is
    rarely deprioritised or filtered.
    """
    if not endpoint.host:
        return ProbeResult(endpoint.name, "", "tcp_connect", None, "ms", False, "no host")
    port = endpoint.port if endpoint.port != 53 else 53
    try:
        start = _now()
        with socket.create_connection((endpoint.host, port), timeout=timeout_s):
            elapsed_ms = (_now() - start) * 1000.0
        return ProbeResult(endpoint.name, endpoint.host, "tcp_connect", elapsed_ms, "ms", True)
    except (TimeoutError, OSError) as exc:
        return ProbeResult(endpoint.name, endpoint.host, "tcp_connect", None, "ms",
                           False, str(exc))


def probe_tls(endpoint: Endpoint, timeout_s: float = 8.0) -> ProbeResult:
    """Time the TLS handshake alone, excluding the TCP setup beneath it."""
    if not endpoint.supports_http:
        return ProbeResult(endpoint.name, endpoint.host, "tls_handshake", None, "ms",
                           False, "endpoint does not serve TLS")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((endpoint.host, 443), timeout=timeout_s) as raw:
            start = _now()
            with ctx.wrap_socket(raw, server_hostname=endpoint.host) as tls:
                elapsed_ms = (_now() - start) * 1000.0
                version = tls.version()
                cipher = tls.cipher()
        return ProbeResult(endpoint.name, endpoint.host, "tls_handshake", elapsed_ms, "ms",
                           True, extra={"tls_version": version,
                                        "cipher": cipher[0] if cipher else None})
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return ProbeResult(endpoint.name, endpoint.host, "tls_handshake", None, "ms",
                           False, str(exc))


def probe_http_ttfb(endpoint: Endpoint, path: str = "/", timeout_s: float = 10.0) -> ProbeResult:
    """Time to first byte — the closest single number to perceived page speed."""
    if not endpoint.supports_http:
        return ProbeResult(endpoint.name, endpoint.host, "http_ttfb", None, "ms",
                           False, "endpoint does not serve HTTP")
    conn: http.client.HTTPSConnection | None = None
    try:
        conn = http.client.HTTPSConnection(endpoint.host, timeout=timeout_s)
        start = _now()
        conn.request("GET", path, headers={"User-Agent": "airframe-kpi/0.1",
                                           "Accept-Encoding": "identity"})
        response = conn.getresponse()
        response.read(1)                       # wait for the first actual byte
        elapsed_ms = (_now() - start) * 1000.0
        return ProbeResult(endpoint.name, endpoint.host, "http_ttfb", elapsed_ms, "ms",
                           True, extra={"status": response.status})
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        return ProbeResult(endpoint.name, endpoint.host, "http_ttfb", None, "ms",
                           False, str(exc))
    finally:
        if conn:
            conn.close()


# ---------------------------------------------------------------- throughput


def iperf3_available() -> bool:
    return shutil.which("iperf3") is not None


def probe_throughput_iperf3(
    server: str, duration_s: int = 5, timeout_s: float = 30.0
) -> ProbeResult:
    """Sustained throughput via iperf3, when a reachable server is configured.

    Requires an iperf3 *server*, which most people do not have on the public
    internet. Included because it is the correct tool and because pointing it at a
    LAN host is the right way to measure Wi-Fi throughput in isolation from the ISP.
    """
    if not iperf3_available():
        return ProbeResult("iperf3", server, "throughput", None, "mbps", False,
                           "iperf3 is not installed (brew install iperf3)")
    try:
        proc = subprocess.run(
            ["iperf3", "-c", server, "-t", str(duration_s), "-J"],
            capture_output=True, text=True, timeout=timeout_s,
        )
        if proc.returncode != 0:
            return ProbeResult("iperf3", server, "throughput", None, "mbps", False,
                               proc.stderr.strip()[:200] or "iperf3 failed")
        import json

        data = json.loads(proc.stdout)
        bps = data["end"]["sum_received"]["bits_per_second"]
        return ProbeResult("iperf3", server, "throughput", bps / 1e6, "mbps", True,
                           method="iperf3",
                           extra={"retransmits": data["end"].get("sum_sent", {}).get("retransmits")})
    except (subprocess.SubprocessError, KeyError, ValueError, OSError) as exc:
        return ProbeResult("iperf3", server, "throughput", None, "mbps", False, str(exc))


def probe_throughput_http(
    endpoint: Endpoint, bytes_wanted: int = 8_000_000, timeout_s: float = 30.0
) -> ProbeResult:
    """Throughput via a bulk HTTP download — the fallback that needs no server.

    Cloudflare's speed endpoint serves an arbitrary number of bytes via
    `/__down?bytes=N`, which makes this a genuine measurement rather than a guess.
    For any other host we fall back to downloading the homepage, which is far too
    small to saturate a link — so that case is reported with a warning rather than
    presented as a throughput figure.
    """
    if not endpoint.supports_http:
        return ProbeResult(endpoint.name, endpoint.host, "throughput", None, "mbps",
                           False, "endpoint does not serve HTTP")

    path = f"/__down?bytes={bytes_wanted}" if "cloudflare" in endpoint.host else "/"
    reliable = "cloudflare" in endpoint.host

    conn: http.client.HTTPSConnection | None = None
    try:
        conn = http.client.HTTPSConnection(endpoint.host, timeout=timeout_s)
        conn.request("GET", path, headers={"User-Agent": "airframe-kpi/0.1",
                                           "Accept-Encoding": "identity"})
        response = conn.getresponse()
        start = _now()
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total >= bytes_wanted:
                break
        elapsed = _now() - start
        if elapsed <= 0 or total == 0:
            return ProbeResult(endpoint.name, endpoint.host, "throughput", None, "mbps",
                               False, "no data transferred")
        mbps = (total * 8) / elapsed / 1e6
        return ProbeResult(
            endpoint.name, endpoint.host, "throughput", mbps, "mbps", True,
            method="http_bulk" if reliable else "http_page",
            extra={"bytes": total, "seconds": round(elapsed, 3),
                   "reliable": reliable,
                   "note": None if reliable else
                           "page too small to saturate the link; indicative only"},
        )
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        return ProbeResult(endpoint.name, endpoint.host, "throughput", None, "mbps",
                           False, str(exc))
    finally:
        if conn:
            conn.close()


# ---------------------------------------------------------------- captive portal


def detect_captive_portal(timeout_s: float = 5.0) -> ProbeResult:
    """Detect a captive portal by asking for a URL with a known-empty response.

    Apple devices use `captive.apple.com/hotspot-detect.html`, which returns exactly
    "Success". Anything else means something is intercepting traffic — and a captive
    portal produces *exactly* the symptom "Wi-Fi connected but nothing works", so
    ruling it out early saves a lot of misdirected debugging.
    """
    conn: http.client.HTTPConnection | None = None
    try:
        conn = http.client.HTTPConnection("captive.apple.com", timeout=timeout_s)
        conn.request("GET", "/hotspot-detect.html",
                     headers={"User-Agent": "CaptiveNetworkSupport/1.0 wispr"})
        response = conn.getresponse()
        body = response.read(2048).decode("utf-8", errors="replace")
        intercepted = "Success" not in body or response.status != 200
        return ProbeResult(
            "captive_portal", "captive.apple.com", "captive_portal",
            1.0 if intercepted else 0.0, "bool", True,
            extra={"status": response.status,
                   "intercepted": intercepted,
                   "body_head": body[:120]},
        )
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        return ProbeResult("captive_portal", "captive.apple.com", "captive_portal",
                           None, "bool", False, str(exc))
    finally:
        if conn:
            conn.close()


# ---------------------------------------------------------------- orchestration


def probe_endpoint(endpoint: Endpoint, *, quick: bool = False) -> list[ProbeResult]:
    """Run every probe appropriate to one endpoint."""
    results: list[ProbeResult] = []
    results.extend(probe_icmp(endpoint, count=3 if quick else 10))
    results.append(probe_tcp_connect(endpoint))
    if endpoint.supports_dns:
        results.append(probe_dns(endpoint))
    if endpoint.supports_http:
        results.append(probe_tls(endpoint))
        results.append(probe_http_ttfb(endpoint))
    return [r for r in results if not (r.error and "does not" in (r.error or ""))]


def probe_all(
    endpoints: list[Endpoint], *, quick: bool = False, include_throughput: bool = True
) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for endpoint in endpoints:
        results.extend(probe_endpoint(endpoint, quick=quick))
    if include_throughput:
        from airframe.kpi.endpoints import by_name

        cf = by_name("cloudflare_edge")
        if cf:
            results.append(probe_throughput_http(cf, bytes_wanted=4_000_000 if quick
                                                 else 12_000_000))
    results.append(detect_captive_portal())
    return results
