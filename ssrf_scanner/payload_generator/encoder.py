"""IP address encoding utilities for SSRF bypass.

Encodes IPv4/IPv6 addresses in various formats that may bypass naive URL parsers:
- Decimal integer (e.g., 169.254.169.254 → 2852039166)
- Hexadecimal (e.g., 0xA9FEA9FE)
- Octal (e.g., 0251.0376.0251.0376)
- Short form (e.g., 127.1 → 127.0.0.1)
- Full IPv6
- IPv4-mapped IPv6 (e.g., ::ffff:169.254.169.254)
"""

import ipaddress
import re
from typing import Optional


class IpEncoder:
    """Encode IP addresses in various bypass formats."""

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def to_decimal(ip: str) -> str:
        """IPv4 → decimal integer (e.g., 169.254.169.254 → 2852039166)."""
        addr = ipaddress.IPv4Address(ip)
        return str(int(addr))

    @staticmethod
    def to_hex(ip: str) -> str:
        """IPv4 → hexadecimal (e.g., 169.254.169.254 → 0xA9FEA9FE)."""
        addr = ipaddress.IPv4Address(ip)
        return f"0x{int(addr):08X}"

    @staticmethod
    def to_octal(ip: str) -> str:
        """IPv4 → octal zero-padded per octet (e.g., 0251.0376.0251.0376)."""
        octets = ip.split(".")
        return ".".join(f"0{int(o):03o}" for o in octets)

    @staticmethod
    def to_short_form(ip: str) -> str:
        """Truncated short form (e.g., 10.0.0.1 → 10.1 when middle octets are zero)."""
        octets = [int(o) for o in ip.split(".")]
        # Only applicable if middle octets are 0
        if octets[1] == 0 and octets[2] == 0:
            return f"{octets[0]}.{octets[3]}"
        if octets[2] == 0:
            return f"{octets[0]}.{octets[1]}.{octets[3]}"
        return ip  # no short form possible

    @staticmethod
    def to_ipv6_loopback() -> str:
        """Return IPv6 loopback variants."""
        return "[::1]"

    @staticmethod
    def to_ipv4_mapped_ipv6(ip: str) -> str:
        """IPv4 → IPv4-mapped IPv6 (e.g., 169.254.169.254 → ::ffff:A9FE:A9FE)."""
        octets = [int(o) for o in ip.split(".")]
        hex_pairs = [f"{octets[0]:02X}{octets[1]:02X}", f"{octets[2]:02X}{octets[3]:02X}"]
        return f"::ffff:{hex_pairs[0]}:{hex_pairs[1]}"

    @staticmethod
    def to_ipv6_full(ip: str) -> str:
        """IPv4 → IPv6 format (e.g., 169.254.169.254 → [::ffff:169.254.169.254])."""
        return f"[::ffff:{ip}]"

    @staticmethod
    def ip_in_cidrs(ip: str, cidrs: list) -> bool:
        """Check if an IP falls in any of the given CIDR ranges."""
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in cidrs:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except (ipaddress.AddressValueError, ValueError):
            pass
        return False
