"""SSRF protection for CIMD metadata fetches."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS: tuple = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


class SSRFValidationError(ValueError):
    """Raised when a client_id URL fails SSRF validation."""


class SSRFValidator:
    """Validates URLs before fetching to prevent SSRF attacks."""

    def __init__(self, max_redirects: int = 3) -> None:
        self.max_redirects = max_redirects

    def validate_redirect_url(self, url: str) -> str:
        return self.validate_url(url, resolve_dns=False)

    def validate_url(self, url: str, resolve_dns: bool = True) -> str:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise SSRFValidationError(
                "client_id must be an HTTPS URL (found scheme %r)" % parsed.scheme
            )
        if not parsed.hostname:
            raise SSRFValidationError("client_id URL must include a hostname")
        if parsed.username or parsed.password:
            raise SSRFValidationError("client_id URL must not contain credentials")
        if resolve_dns:
            self._validate_dns(parsed.hostname)
        return url

    def _validate_dns(self, hostname: str) -> None:
        try:
            infos = socket.getaddrinfo(
                hostname, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise SSRFValidationError(
                f"DNS resolution failed for {hostname!r}: {exc}"
            ) from exc
        if not infos:
            raise SSRFValidationError(
                f"No addresses resolved for hostname {hostname!r}"
            )
        for info in infos:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise SSRFValidationError(f"Invalid IP address {ip_str!r}") from exc
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    raise SSRFValidationError(
                        f"Hostname {hostname!r} resolves to blocked address {ip}"
                    )

    def lookup(self, url: str) -> tuple[str, str]:
        """Resolve the URL's hostname and return (url, pinned_ip)."""
        parsed = urlparse(url)
        if not parsed.hostname:
            raise SSRFValidationError("client_id URL must include a hostname")
        self._validate_dns(parsed.hostname)
        infos = socket.getaddrinfo(
            parsed.hostname,
            parsed.port or 443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        if not infos:
            raise SSRFValidationError(
                f"No addresses resolved for hostname {parsed.hostname!r}"
            )
        pinned_ip = infos[0][4][0]
        return url, pinned_ip