"""Measurement endpoints, chosen for the Indian network context.

Endpoint selection *is* the experiment design. A latency number is meaningless
without knowing what it was measured against, and the choice of target determines
which layer a regression can be attributed to:

* **gateway** — the local router. This is the control. If gateway latency is fine
  but everything else is slow, the Wi-Fi link is healthy and the problem is
  upstream. If the gateway itself is slow, it is a radio or LAN problem. Without
  this endpoint you cannot separate "my Wi-Fi is bad" from "my ISP is bad", which
  is the single most common misdiagnosis in consumer networking.

* **ISP resolvers (Jio, Airtel, BSNL)** — measures the path to the ISP's own
  infrastructure. DNS resolution time against your own ISP's resolver is a
  remarkably good proxy for last-mile health, and it is the layer users feel first
  because every page load starts with a lookup.

* **Indian CDN/cloud edges (Mumbai, Chennai, Delhi PoPs)** — where content actually
  lives for Indian users. Most traffic terminates at a CDN edge a few tens of
  milliseconds away, not at a distant origin.

* **an international reference** — deliberately included as a contrast. A ~120ms+
  RTT to a far endpoint alongside a ~20ms RTT to Mumbai is *correct behaviour*, not
  a regression. Having both prevents a threshold tuned on one from misjudging the
  other.

On why this matters for the JD: characterising performance over Indian ISP networks
means knowing that a 40ms p50 to a Mumbai PoP is good, that Jio and Airtel have
materially different last-mile characteristics, and that a single global latency
threshold would be wrong for every one of them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EndpointRole(str, Enum):
    CONTROL = "control"          # local gateway: isolates Wi-Fi from WAN
    ISP_DNS = "isp_dns"          # the ISP's own resolver: last-mile health
    PUBLIC_DNS = "public_dns"    # anycast resolver: routing quality
    CDN_EDGE = "cdn_edge"        # where content actually is
    INTERNATIONAL = "international"  # far reference, for contrast


@dataclass(frozen=True)
class Endpoint:
    name: str
    host: str
    role: EndpointRole
    description: str
    #: Expected p50 RTT in ms on a healthy Indian broadband connection. Used as a
    #: sanity bound, NOT as a pass/fail threshold — thresholds come from measured
    #: baselines (see kpi/regression.py), because a hardcoded number cannot know
    #: whether you are on fibre in Bengaluru or 4G in a small town.
    expected_rtt_ms: float = 50.0
    supports_http: bool = False
    supports_dns: bool = False
    port: int = 443


ENDPOINTS: tuple[Endpoint, ...] = (
    # ---- control ----
    Endpoint(
        "gateway", "",                      # host filled in at runtime
        EndpointRole.CONTROL,
        "local default gateway — isolates Wi-Fi problems from ISP problems",
        expected_rtt_ms=5.0, port=80,
    ),
    # ---- Indian ISP resolvers ----
    Endpoint(
        "jio_dns", "49.45.45.45",
        EndpointRole.ISP_DNS,
        "Reliance Jio public resolver",
        expected_rtt_ms=35.0, supports_dns=True, port=53,
    ),
    Endpoint(
        "airtel_dns", "202.56.230.5",
        EndpointRole.ISP_DNS,
        "Bharti Airtel resolver",
        expected_rtt_ms=40.0, supports_dns=True, port=53,
    ),
    Endpoint(
        "bsnl_dns", "218.248.240.1",
        EndpointRole.ISP_DNS,
        "BSNL resolver",
        expected_rtt_ms=60.0, supports_dns=True, port=53,
    ),
    # ---- anycast resolvers (usually terminate in-country) ----
    Endpoint(
        "cloudflare_dns", "1.1.1.1",
        EndpointRole.PUBLIC_DNS,
        "Cloudflare anycast resolver — nearest PoP, usually Mumbai or Chennai",
        expected_rtt_ms=20.0, supports_dns=True, port=53,
    ),
    Endpoint(
        "google_dns", "8.8.8.8",
        EndpointRole.PUBLIC_DNS,
        "Google Public DNS anycast",
        expected_rtt_ms=25.0, supports_dns=True, port=53,
    ),
    # ---- CDN / cloud edges serving India ----
    Endpoint(
        "cloudflare_edge", "speed.cloudflare.com",
        EndpointRole.CDN_EDGE,
        "Cloudflare edge with a throughput endpoint; Indian PoP",
        expected_rtt_ms=25.0, supports_http=True,
    ),
    Endpoint(
        "google_in", "www.google.co.in",
        EndpointRole.CDN_EDGE,
        "Google India frontend",
        expected_rtt_ms=30.0, supports_http=True,
    ),
    Endpoint(
        "apple_cdn", "www.apple.com",
        EndpointRole.CDN_EDGE,
        "Apple CDN edge — relevant given the target platform",
        expected_rtt_ms=35.0, supports_http=True,
    ),
    # ---- international reference ----
    Endpoint(
        "international_ref", "www.cloudflare.com",
        EndpointRole.INTERNATIONAL,
        "far reference: high RTT here is expected, not a regression",
        expected_rtt_ms=120.0, supports_http=True,
    ),
)


def by_name(name: str) -> Endpoint | None:
    return next((e for e in ENDPOINTS if e.name == name), None)


def by_role(role: EndpointRole) -> list[Endpoint]:
    return [e for e in ENDPOINTS if e.role is role]


def resolve_gateway(gateway_ip: str | None) -> list[Endpoint]:
    """Return the endpoint list with the gateway's real address filled in.

    The gateway is discovered at runtime (it differs per network), so the static
    table carries a placeholder and this substitutes the live value. Where no
    gateway can be found, the control endpoint is dropped rather than probed with
    an empty host.
    """
    out: list[Endpoint] = []
    for e in ENDPOINTS:
        if e.name == "gateway":
            if gateway_ip:
                out.append(
                    Endpoint(e.name, gateway_ip, e.role, e.description,
                             e.expected_rtt_ms, e.supports_http, e.supports_dns, e.port)
                )
            continue
        out.append(e)
    return out


#: A small, fast subset for tests and for CI-adjacent runs. Probing ten endpoints
#: takes real seconds, and a test suite nobody waits for is a test suite nobody runs.
QUICK_SET = ("gateway", "cloudflare_dns", "google_dns", "cloudflare_edge")
