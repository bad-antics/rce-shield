"""
Gaming Network Exposure Scanner

Audits network security for gamers:
- Open port enumeration (game servers, voice chat, streaming)
- UPnP/NAT-PMP exposure audit
- Game streaming service security (Parsec, Moonlight, Steam Link)
- Voice chat protocol analysis (Discord RPC, TeamSpeak query)
- DDoS protection assessment
"""

import socket
import subprocess
from pathlib import Path
from typing import Optional

import psutil

from rce_shield.core.scanner import BaseScanner, Finding, Severity


class NetworkScanner(BaseScanner):
    name = "Gaming Network Scanner"
    description = "Audits network exposure for gaming services"

    # Known gaming ports and their services
    GAMING_PORTS = {
        # Game servers
        27015: ("Source Engine", "Valve games (CS2, TF2, L4D2)"),
        27016: ("Source Engine RCON", "Remote console — HIGH RISK if exposed"),
        25565: ("Minecraft Server", "Minecraft Java Edition"),
        19132: ("Minecraft Bedrock", "Minecraft Bedrock Edition"),
        7777: ("Unreal Engine", "Common UE4/UE5 game server port"),
        7778: ("Unreal Engine Query", "Server browser query"),
        2302: ("Arma/DayZ", "Arma series game server"),
        64738: ("Mumble", "Mumble voice server"),

        # Voice / Communication
        6463: ("Discord RPC", "Discord Rich Presence (local only expected)"),
        6464: ("Discord RPC Alt", "Discord RPC alternate"),
        9987: ("TeamSpeak", "TeamSpeak voice server"),
        10011: ("TeamSpeak Query", "TeamSpeak ServerQuery — HIGH RISK"),
        30033: ("TeamSpeak File Transfer", "TeamSpeak file transfer"),

        # Game streaming
        47984: ("NVIDIA GameStream", "NVIDIA Shield streaming"),
        47989: ("NVIDIA GameStream HTTPS", "NVIDIA Shield streaming control"),
        48010: ("NVIDIA GameStream RTSP", "Video stream"),
        47998: ("Moonlight/Sunshine", "Moonlight game streaming"),
        47999: ("Moonlight/Sunshine", "Moonlight streaming control"),
        48000: ("Moonlight/Sunshine", "Moonlight streaming data"),
        8040: ("Parsec", "Parsec game streaming"),

        # Game launchers
        27036: ("Steam Remote Play", "Steam in-home streaming"),
        27037: ("Steam Remote Play", "Steam in-home streaming data"),

        # Remote access
        3389: ("RDP", "Remote Desktop — CRITICAL if exposed to internet"),
        5900: ("VNC", "VNC remote desktop — CRITICAL if exposed"),

        # Common attack targets
        4444: ("Metasploit Default", "Common reverse shell port"),
        5555: ("ADB/Reverse Shell", "Android Debug Bridge / reverse shell"),
        1337: ("Elite/Backdoor", "Common backdoor port"),
        31337: ("Back Orifice", "Historic backdoor port"),
        9999: ("Reverse Shell", "Common reverse shell port"),
    }

    # Critical ports that should never be exposed to the internet
    CRITICAL_PORTS = {3389, 5900, 4444, 5555, 1337, 31337, 9999, 27016, 10011}

    def scan(self) -> list[Finding]:
        self._scan_listening_ports()
        self._check_upnp()
        self._check_firewall()
        self._scan_game_streaming()
        self._check_ddos_protection()
        return self.findings

    def _scan_listening_ports(self):
        """Enumerate all listening ports and flag gaming-related services."""
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.add_finding(
                Severity.INFO, "network", "System",
                "Insufficient permissions to enumerate network connections",
                remediation="Run rce-shield with elevated privileges (sudo/admin)",
            )
            return

        listening = [c for c in connections if c.status == "LISTEN"]

        for conn in listening:
            port = conn.laddr.port
            addr = conn.laddr.ip
            pid = conn.pid

            proc_name = "unknown"
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Check against known gaming ports
            if port in self.GAMING_PORTS:
                service, desc = self.GAMING_PORTS[port]

                # Determine severity based on port
                if port in self.CRITICAL_PORTS:
                    severity = Severity.CRITICAL
                elif "RCON" in desc or "Query" in desc or "RISK" in desc:
                    severity = Severity.HIGH
                elif "stream" in desc.lower():
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                # Check if bound to all interfaces (0.0.0.0)
                is_exposed = addr in ("0.0.0.0", "::", "")
                if is_exposed and severity.sort_key() > 1:
                    severity = Severity(["CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW"][severity.sort_key()])

                self.add_finding(
                    severity, "network", f"{service} (:{port})",
                    f"{desc} — {'Exposed to all interfaces' if is_exposed else 'Local only'}",
                    evidence=f"Process: {proc_name} (PID: {pid}), Bind: {addr}:{port}",
                    remediation=f"{'Bind to localhost only' if is_exposed else 'Acceptable'}"
                    f"{'; Consider firewall rule' if severity.sort_key() <= 1 else ''}",
                )

            # Flag any port below 1024 that isn't a standard service
            elif port < 1024 and port not in {22, 53, 80, 443, 993, 995}:
                self.add_finding(
                    Severity.MEDIUM, "network", f"Port {port}",
                    f"Unusual privileged port listening: {port}",
                    evidence=f"Process: {proc_name} (PID: {pid})",
                    remediation="Verify this service is expected",
                )

    def _check_upnp(self):
        """Check for UPnP port forwarding exposure."""
        # Try to discover UPnP devices
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(3)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            msearch = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                "\r\n"
            )

            sock.sendto(msearch.encode(), ("239.255.255.250", 1900))

            responses = []
            try:
                while True:
                    data, addr = sock.recvfrom(65507)
                    responses.append((data.decode("utf-8", errors="replace"), addr))
            except socket.timeout:
                pass
            finally:
                sock.close()

            if responses:
                self.add_finding(
                    Severity.MEDIUM, "network", "UPnP Gateway",
                    f"UPnP Internet Gateway Device found ({len(responses)} responses)",
                    evidence=f"Gateway: {responses[0][1][0]}",
                    remediation=(
                        "Disable UPnP on your router. "
                        "Manually forward only required game ports. "
                        "UPnP allows any malware to open firewall ports."
                    ),
                )
            else:
                self.add_finding(
                    Severity.INFO, "network", "UPnP",
                    "No UPnP gateway detected (good)",
                )

        except OSError:
            pass

    def _check_firewall(self):
        """Check if system firewall is enabled."""
        if self.is_windows:
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    if "OFF" in result.stdout:
                        self.add_finding(
                            Severity.CRITICAL, "network", "Windows Firewall",
                            "Windows Firewall is DISABLED on one or more profiles",
                            evidence=result.stdout.strip()[:200],
                            remediation="Enable Windows Firewall immediately: netsh advfirewall set allprofiles state on",
                        )
                    else:
                        self.add_finding(
                            Severity.INFO, "network", "Windows Firewall",
                            "Windows Firewall is enabled",
                        )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        elif self.is_linux:
            # Check iptables/nftables/ufw
            firewall_found = False
            for cmd, name in [("ufw status", "UFW"), ("iptables -L -n", "iptables")]:
                try:
                    result = subprocess.run(
                        cmd.split(), capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0:
                        output = result.stdout
                        if "inactive" in output.lower() or "Status: inactive" in output:
                            self.add_finding(
                                Severity.HIGH, "network", name,
                                f"{name} firewall is inactive",
                                remediation=f"Enable {name}: sudo ufw enable",
                            )
                        else:
                            firewall_found = True
                            self.add_finding(
                                Severity.INFO, "network", name,
                                f"{name} firewall is active",
                            )
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
                    pass

            if not firewall_found:
                self.add_finding(
                    Severity.HIGH, "network", "Firewall",
                    "No active firewall detected",
                    remediation="Install and enable ufw: sudo apt install ufw && sudo ufw enable",
                )

    def _scan_game_streaming(self):
        """Check game streaming service configurations."""
        # Check for NVIDIA GameStream / Sunshine
        streaming_ports = {47984, 47989, 48010, 47998, 47999, 48000}
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status == "LISTEN" and conn.laddr.port in streaming_ports:
                    if conn.laddr.ip in ("0.0.0.0", "::"):
                        self.add_finding(
                            Severity.HIGH, "streaming", "Game Streaming",
                            f"Game streaming exposed on all interfaces (port {conn.laddr.port})",
                            remediation="Restrict streaming to local network via firewall rules",
                        )
        except psutil.AccessDenied:
            pass

    def _check_ddos_protection(self):
        """Basic DDoS protection assessment."""
        # Check SYN cookie protection (Linux)
        if self.is_linux:
            try:
                syncookies = Path("/proc/sys/net/ipv4/tcp_syncookies").read_text().strip()
                if syncookies != "1":
                    self.add_finding(
                        Severity.MEDIUM, "network", "DDoS Protection",
                        "TCP SYN cookies disabled — vulnerable to SYN flood",
                        remediation="echo 1 > /proc/sys/net/ipv4/tcp_syncookies",
                    )
            except (FileNotFoundError, PermissionError):
                pass

            # Check ICMP rate limiting
            try:
                icmp_limit = Path("/proc/sys/net/ipv4/icmp_ratelimit").read_text().strip()
                if int(icmp_limit) == 0:
                    self.add_finding(
                        Severity.LOW, "network", "DDoS Protection",
                        "ICMP rate limiting disabled",
                        remediation="echo 1000 > /proc/sys/net/ipv4/icmp_ratelimit",
                    )
            except (FileNotFoundError, PermissionError, ValueError):
                pass
