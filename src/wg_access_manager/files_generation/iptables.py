from dataclasses import dataclass
from typing import Iterable

from wg_access_manager.data.base import (
    User,
    Service,
    Permission,
)

import shlex
import ipaddress
import socket
from pathlib import Path


@dataclass
class NetConfig:
    wg_iface: str = "wg0"
    lan_iface: str = "eth0"  # server container's LAN-facing iface
    docker_iface: str = "eth0"  # server container's iface reaching Pi-hole net
    chain_vpn: str = "WG_VPN_ACL"
    chain_lan: str = "WG_VPN_LAN"
    chain_docker: str = "WG_VPN_DOCKER"
    log_prefix_vpn: str = "WG-ACL VPN "
    log_prefix_lan: str = "WG-ACL LAN "
    log_prefix_docker: str = "WG-ACL DOCKER "
    pihole_ip: str  # e.g., "172.20.0.3"
    lan_cidr: ipaddress.IPv4Network = ipaddress.IPv4Network("192.168.1.0/24")
    default_reject: bool = True
    allow_icmp_on_any_allow: bool = True
    enable_nat_lan_to_vpn: bool = True  # only if you cannot add a LAN route


PortSpec = list[tuple[str, int]]


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_name(name_or_ip: str) -> str:
    """Resolve once at generation time; returns the first IPv4 address."""
    if is_ip(name_or_ip):
        return name_or_ip
    # getent-like resolution; prefer IPv4
    infos = socket.getaddrinfo(
        name_or_ip, None, family=socket.AF_INET, type=socket.SOCK_STREAM
    )
    if not infos:
        raise RuntimeError(f"Cannot resolve hostname: {name_or_ip}")
    return infos[0][4][0]


def normalize_ports(ports: None | dict | list) -> PortSpec:
    """
    Accepts:
      - {"tcp":[80,443], "udp":[53]}
      - ["tcp/80", "udp/53", "443"]
      - [80, 443]
      - None -> []
    Returns: [("tcp",80), ("tcp",443), ("udp",53)]
    """
    out: PortSpec = []
    if ports is None:
        return out
    if isinstance(ports, dict):
        for proto, lst in ports.items():
            proto_norm = str(proto).lower()
            for p in lst:
                out.append((proto_norm, int(p)))
        return out
    if isinstance(ports, list):
        for item in ports:
            if isinstance(item, int):
                out.append(("tcp", int(item)))
            else:
                s = str(item).strip().lower()
                if "/" in s:
                    proto, port = s.split("/", 1)
                    out.append((proto.strip(), int(port)))
                else:
                    out.append(("tcp", int(s)))
        return out
    raise TypeError(f"Unsupported ports type: {type(ports)}")


class AclBuilder:
    def __init__(
        self,
        cfg: NetConfig,
        users: Iterable[User],
        services: Iterable[Service],
        permissions: Iterable[Permission],
    ):
        self.cfg = cfg
        self.users = {u.name: u for u in users}
        self.services = {s.name: s for s in services}
        self.permissions = [p for p in permissions if p.allowed]

    # ── Chains UP ─────────────────────────────────────────────────────────────
    def _prologue_up(self) -> list[str]:
        c = self.cfg
        q = shlex.quote
        cmds = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            "# === Generated WireGuard ACLs ===",
            f"WG_IF={q(c.wg_iface)}",
            f"LAN_IF={q(c.lan_iface)}",
            f"DOCKER_IF={q(c.docker_iface)}",
            "",
            f"iptables -N {q(c.chain_vpn)} 2>/dev/null || true",
            f"iptables -F {q(c.chain_vpn)}",
            f"iptables -N {q(c.chain_lan)} 2>/dev/null || true",
            f"iptables -F {q(c.chain_lan)}",
            f"iptables -N {q(c.chain_docker)} 2>/dev/null || true",
            f"iptables -F {q(c.chain_docker)}",
            "",
            "# Track established flows early in each chain",
            f"iptables -A {q(c.chain_vpn)} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"iptables -A {q(c.chain_lan)} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"iptables -A {q(c.chain_docker)} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "",
            "# Hook chains into FORWARD (idempotent)",
            f'iptables -C FORWARD -i "$WG_IF" -o "$WG_IF" -j {q(c.chain_vpn)} 2>/dev/null || '
            f'iptables -I FORWARD 1 -i "$WG_IF" -o "$WG_IF" -j {q(c.chain_vpn)}',
            f'iptables -C FORWARD -i "$LAN_IF" -o "$WG_IF" -j {q(c.chain_lan)} 2>/dev/null || '
            f'iptables -I FORWARD 1 -i "$LAN_IF" -o "$WG_IF" -j {q(c.chain_lan)}',
            f'iptables -C FORWARD -i "$WG_IF" -o "$LAN_IF" -j {q(c.chain_lan)} 2>/dev/null || '
            f'iptables -I FORWARD 1 -i "$WG_IF" -o "$LAN_IF" -j {q(c.chain_lan)}',
            f'iptables -C FORWARD -i "$WG_IF" -o "$DOCKER_IF" -j {q(c.chain_docker)} 2>/dev/null || '
            f'iptables -I FORWARD 1 -i "$WG_IF" -o "$DOCKER_IF" -j {q(c.chain_docker)}',
            f'iptables -C FORWARD -i "$DOCKER_IF" -o "$WG_IF" -j {q(c.chain_docker)} 2>/dev/null || '
            f'iptables -I FORWARD 1 -i "$DOCKER_IF" -o "$WG_IF" -j {q(c.chain_docker)}',
            "",
        ]
        return cmds

    # ── VPN↔VPN (wg0→wg0) allows from Permission list ────────────────────────
    def _vpn_acl_rules(self) -> list[str]:
        c = self.cfg
        q = shlex.quote
        lines: list[str] = []
        for perm in self.permissions:
            u = self.users.get(perm.user_name)
            s = self.services.get(perm.service_name)
            if not u:
                raise ValueError(f"Unknown user in permission: {perm.user_name}")
            if not s:
                raise ValueError(f"Unknown service in permission: {perm.service_name}")

            dst_ip = resolve_name(s.ip)
            ports = normalize_ports(s.ports)

            cm_base = f"{perm.user_name}->{perm.service_name}"
            if not ports:
                if c.allow_icmp_on_any_allow:
                    lines.append(
                        f'iptables -A {q(c.chain_vpn)} -i "$WG_IF" -o "$WG_IF" -s {u.ip} -d {dst_ip} -p icmp '
                        f"-m comment --comment {q(cm_base + ':icmp')} -j ACCEPT"
                    )
                lines.append(
                    f'iptables -A {q(c.chain_vpn)} -i "$WG_IF" -o "$WG_IF" -s {u.ip} -d {dst_ip} '
                    f"-m comment --comment {q(cm_base + ':all')} -j ACCEPT"
                )
                continue

            for proto, port in ports:
                proto = proto.lower()
                if proto not in ("tcp", "udp"):
                    raise ValueError(
                        f"Unsupported proto '{proto}' for service '{s.name}'"
                    )
                lines.append(
                    f'iptables -A {q(c.chain_vpn)} -i "$WG_IF" -o "$WG_IF" '
                    f"-s {u.ip} -d {dst_ip} -p {proto} --dport {int(port)} "
                    f"-m comment --comment {q(f'{cm_base}:{proto}/{int(port)}')} -j ACCEPT"
                )
        # Default action
        if c.default_reject:
            if c.log_prefix_vpn:
                lines.append(
                    f"iptables -A {q(c.chain_vpn)} -m limit --limit 10/min -j LOG --log-prefix {q(c.log_prefix_vpn)} --log-level 6"
                )
            lines.append(
                f"iptables -A {q(c.chain_vpn)} -j REJECT --reject-with icmp-port-unreachable"
            )
        return lines

    def _lan_policy_rules(self) -> list[str]:
        c = self.cfg
        q = shlex.quote
        lines: list[str] = []

        # Allow LAN → VPN unconditionally
        lines.append(f'iptables -A {q(c.chain_lan)} -i "$LAN_IF" -o "$WG_IF" -j ACCEPT')

        # Blanket VPN → LAN for users in the "lan" group
        # (assumes User has: groups: list[str] | None)
        for u in self.users.values():
            groups = getattr(u, "groups", None)
            if not groups:
                continue
            # case-insensitive membership check
            if any(g.lower() == "lan" for g in groups):
                lines.append(
                    f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" '
                    f"-s {u.ip} -d {c.lan_cidr} "
                    f"-m comment --comment {q(f'VPN->LAN blanket: {u.name}')} -j ACCEPT"
                )

        # Default deny VPN → LAN
        if c.default_reject:
            if c.log_prefix_lan:
                lines.append(
                    f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" '
                    f"-m limit --limit 10/min -j LOG "
                    f"--log-prefix {q(c.log_prefix_lan)} --log-level 6"
                )
            lines.append(
                f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" '
                f"-j REJECT --reject-with icmp-port-unreachable"
            )

        return lines

    # ── WG↔Docker policy: allow DNS to Pi-hole, deny rest ────────────────────
    def _docker_policy_rules(self) -> list[str]:
        c = self.cfg
        q = shlex.quote
        lines: list[str] = []
        if c.pihole_ip:
            pihole_ip = resolve_name(c.pihole_ip)
            lines += [
                # Lines for the DNS ports
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -d {pihole_ip} -p udp --dport 53 -j ACCEPT',
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -d {pihole_ip} -p tcp --dport 53 -j ACCEPT',
                # Lines for the HTTP and HTTPS ports
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -d {pihole_ip} -p tcp --dport 80 -j ACCEPT',
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -d {pihole_ip} -p tcp --dport 443 -j ACCEPT',
            ]
        # Allow Docker → WG unconditionally
        lines.append(
            f'iptables -A {q(c.chain_docker)} -i "$DOCKER_IF" -o "$WG_IF" -j ACCEPT'
        )

        # Blanket WG → Docker for users in the "wg_docker" group
        for u in self.users.values():
            groups = getattr(u, "groups", None)
            if not groups:
                continue
            if any(g.lower() == "wg_docker" for g in groups):
                lines.append(
                    f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" '
                    f"-s {u.ip} "
                    f"-m comment --comment {q(f'WG->Docker blanket: {u.name}')} -j ACCEPT"
                )
        # Default deny WG → Docker
        if c.default_reject:
            if c.log_prefix_docker:
                lines.append(
                    f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -m limit --limit 10/min -j LOG --log-prefix {q(c.log_prefix_docker)} --log-level 6'
                )
            lines.append(
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -j REJECT --reject-with icmp-port-unreachable'
            )
        return lines

    # ── Optional NAT when you can't add a route on the LAN router ────────────
    def _nat_rules_up(self) -> list[str]:
        c = self.cfg
        lines: list[str] = []
        # LAN → VPN MASQUERADE (last resort)
        if c.enable_nat_lan_to_vpn:
            lines.append(
                'iptables -t nat -C POSTROUTING -o "$WG_IF" -s 192.168.0.0/16 -d 10.0.0.0/8 -j MASQUERADE 2>/dev/null || '
                'iptables -t nat -A POSTROUTING -o "$WG_IF" -s 192.168.0.0/16 -d 10.0.0.0/8 -j MASQUERADE'
            )
        # VPN → LAN MASQUERADE (last resort)
        if c.enable_nat_vpn_to_lan:
            lines.append(
                'iptables -t nat -C POSTROUTING -o "$LAN_IF" -s 10.0.0.0/8 -d 192.168.0.0/16 -j MASQUERADE 2>/dev/null || '
                'iptables -t nat -A POSTROUTING -o "$LAN_IF" -s 10.0.0.0/8 -d 192.168.0.0/16 -j MASQUERADE'
            )
        return lines

    # ── Chains DOWN (cleanup) ────────────────────────────────────────────────
    def _epilogue_down(self) -> list[str]:
        c = self.cfg
        q = shlex.quote
        return [
            "",
            "case ${1:-up} in",
            "  up)",
            "    exit 0;;",
            "  down)",
            f'    iptables -D FORWARD -i "$WG_IF" -o "$WG_IF" -j {q(c.chain_vpn)} 2>/dev/null || true',
            f'    iptables -D FORWARD -i "$LAN_IF" -o "$WG_IF" -j {q(c.chain_lan)} 2>/dev/null || true',
            f'    iptables -D FORWARD -i "$WG_IF" -o "$LAN_IF" -j {q(c.chain_lan)} 2>/dev/null || true',
            f'    iptables -D FORWARD -i "$WG_IF" -o "$DOCKER_IF" -j {q(c.chain_docker)} 2>/dev/null || true',
            f'    iptables -D FORWARD -i "$DOCKER_IF" -o "$WG_IF" -j {q(c.chain_docker)} 2>/dev/null || true',
            f"    iptables -F {q(c.chain_vpn)} 2>/dev/null || true",
            f"    iptables -F {q(c.chain_lan)} 2>/dev/null || true",
            f"    iptables -F {q(c.chain_docker)} 2>/dev/null || true",
            f"    iptables -X {q(c.chain_vpn)} 2>/dev/null || true",
            f"    iptables -X {q(c.chain_lan)} 2>/dev/null || true",
            f"    iptables -X {q(c.chain_docker)} 2>/dev/null || true",
            "    # Optional NAT cleanup: flush specific rules if you added them via -A",
            "    # (Skipped here; use unique comments if you need explicit deletions.)",
            "    ;;",
            '  *) echo "Usage: $0 {up|down}" >&2; exit 2;;',
            "esac",
            "# === End ===",
        ]

    def build_script(self) -> list[str]:
        lines: list[str] = []
        lines += self._prologue_up()
        lines += self._vpn_acl_rules()
        lines += self._lan_policy_rules()
        lines += self._docker_policy_rules()
        lines += self._nat_rules_up()
        lines += self._epilogue_down()
        return lines


def write_script(path: str | Path, commands: Iterable[str]) -> Path:
    p = Path(path)
    p.write_text("\n".join(commands) + "\n", encoding="utf-8")
    p.chmod(0o750)
    return p
