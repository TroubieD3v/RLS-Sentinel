"""Network target allowlist and SSRF protection for user-supplied database targets.

Policy is configuration-driven (``SENTINEL_ALLOWED_TARGETS``): hostnames, IPs or CIDR ranges.
The default allows loopback only; private ranges (RFC 1918) are NOT globally blocked, an operator
must opt in to the ranges that host authorized databases.

The resolved address is pinned (passed to libpq as ``hostaddr``) so a DNS answer cannot change
between validation and connection (DNS rebinding / TOCTOU).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from ..errors import ConnectionRefusedByPolicy

# Always refused, even when a broad CIDR is allowlisted (cloud metadata services).
_ALWAYS_DENY = [
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.170.2/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("100.100.100.200/32"),
]


@dataclass(frozen=True)
class ResolvedTarget:
    host: str
    port: int
    hostaddr: str


def _parse_rules(rules: list[str]) -> tuple[list[str], list[ipaddress._BaseNetwork]]:
    names: list[str] = []
    nets: list[ipaddress._BaseNetwork] = []
    for r in rules:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            names.append(r.lower())
    return names, nets


def resolve_allowed(host: str, port: int, allowed: list[str]) -> ResolvedTarget:
    """Resolve ``host`` and verify every resulting address against the allowlist."""
    if not host:
        raise ConnectionRefusedByPolicy("Connection target has no host (unix sockets are not accepted).")
    names, nets = _parse_rules(allowed)
    host_l = host.lower()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectionRefusedByPolicy(f"Cannot resolve target host '{host}'.") from exc
    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        addrs.append(ip)
    if not addrs:
        raise ConnectionRefusedByPolicy(f"No addresses for '{host}'.")
    for ip in addrs:
        if any(ip in d for d in _ALWAYS_DENY if d.version == ip.version):
            raise ConnectionRefusedByPolicy("Target resolves to a blocked metadata address.")
    name_ok = host_l in names
    for ip in addrs:
        ip_ok = any(ip in n for n in nets if n.version == ip.version)
        if not (ip_ok or name_ok):
            raise ConnectionRefusedByPolicy(
                f"Target '{host}' ({ip}) is not in SENTINEL_ALLOWED_TARGETS. "
                "Add the hostname or CIDR range of the authorized database to the allowlist.",
                detail={"host": host, "resolved": str(ip)},
            )
    # Prefer IPv4 for pinning stability; every address already passed the allowlist check.
    pick = next((a for a in addrs if a.version == 4), addrs[0])
    return ResolvedTarget(host=host, port=port, hostaddr=str(pick))
