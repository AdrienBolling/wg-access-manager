from dataclasses import dataclass


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
    default_reject: bool = True
    allow_icmp_on_any_allow: bool = True
    enable_nat_lan_to_vpn: bool = True  # only if you cannot add a LAN route


class AclBuilder:
    def __init__(
        self,
        cfg: NetConfig,
        users: Iterable[User],
        services: Iterable[Service],
        permissions: Iterable[Permission],
        lan_permissions: Iterable[LanPermission] | None = None,
    ):
        self.cfg = cfg
        self.users = {u.name: u for u in users}
        self.services = {s.name: s for s in services}
        self.permissions = [p for p in permissions if p.allowed]
        self.lan_permissions = [p for p in (lan_permissions or []) if p.allowed]

    # ── Chains UP ─────────────────────────────────────────────────────────────
    def _prologue_up(self) -> List[str]:
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
    def _vpn_acl_rules(self) -> List[str]:
        c = self.cfg
        q = shlex.quote
        lines: List[str] = []
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

    # ── LAN↔VPN policy: LAN→VPN allowed; VPN→LAN selective ───────────────────
    def _lan_policy_rules(self) -> List[str]:
        c = self.cfg
        q = shlex.quote
        lines: List[str] = []
        # Allow LAN → VPN unconditionally
        lines.append(f'iptables -A {q(c.chain_lan)} -i "$LAN_IF" -o "$WG_IF" -j ACCEPT')

        # Selective VPN → LAN
        for lp in self.lan_permissions:
            u = self.users.get(lp.user_name)
            if not u:
                raise ValueError(f"Unknown user in LAN permission: {lp.user_name}")
            dst_ip = resolve_name(lp.dst)
            ports = normalize_ports(lp.ports)
            if not ports:
                # allow all to that LAN host (rare; explicit)
                lines.append(
                    f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" -s {u.ip} -d {dst_ip} '
                    f"-m comment --comment {q('VPN->LAN:' + lp.user_name + '->' + dst_ip + ':all')} -j ACCEPT"
                )
            else:
                for proto, port in ports:
                    proto = proto.lower()
                    if proto not in ("tcp", "udp"):
                        raise ValueError(
                            f"Unsupported proto '{proto}' in LAN permission"
                        )
                    lines.append(
                        f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" -s {u.ip} -d {dst_ip} '
                        f"-p {proto} --dport {int(port)} "
                        f"-m comment --comment {q('VPN->LAN:' + lp.user_name + '->' + dst_ip + f':{proto}/{int(port)}')} -j ACCEPT"
                    )

        # Default deny VPN → LAN
        if c.default_reject:
            if c.log_prefix_lan:
                lines.append(
                    f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" -m limit --limit 10/min -j LOG --log-prefix {q(c.log_prefix_lan)} --log-level 6'
                )
            lines.append(
                f'iptables -A {q(c.chain_lan)} -i "$WG_IF" -o "$LAN_IF" -j REJECT --reject-with icmp-port-unreachable'
            )
        return lines

    # ── WG↔Docker policy: allow DNS to Pi-hole, deny rest ────────────────────
    def _docker_policy_rules(self) -> List[str]:
        c = self.cfg
        q = shlex.quote
        lines: List[str] = []
        if c.pihole_ip:
            pihole_ip = resolve_name(c.pihole_ip)
            lines += [
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -d {pihole_ip} -p udp --dport 53 -j ACCEPT',
                f'iptables -A {q(c.chain_docker)} -i "$WG_IF" -o "$DOCKER_IF" -d {pihole_ip} -p tcp --dport 53 -j ACCEPT',
            ]
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
    def _nat_rules_up(self) -> List[str]:
        c = self.cfg
        lines: List[str] = []
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
    def _epilogue_down(self) -> List[str]:
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

    def build_script(self) -> List[str]:
        lines: List[str] = []
        lines += self._prologue_up()
        lines += self._vpn_acl_rules()
        lines += self._lan_policy_rules()
        lines += self._docker_policy_rules()
        lines += self._nat_rules_up()
        lines += self._epilogue_down()
        return lines
