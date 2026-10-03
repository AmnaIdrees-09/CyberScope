import ipaddress
import socket


class UnsafeHostError(Exception):
    """Raised when a hostname resolves to a private, loopback, or otherwise non-public address."""


def resolve_public_ip(hostname: str) -> str:
    """
    Resolves a hostname and raises UnsafeHostError if it points anywhere
    that isn't a genuine public internet address. This is the core SSRF
    guard: without it, a visitor could ask the backend to "check the SSL
    certificate" or "check the headers" of an internal service (like
    169.254.169.254, a cloud metadata endpoint, or 127.0.0.1) and use our
    server as a proxy to reach it.
    """
    try:
        ip_str = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise UnsafeHostError(f"Could not resolve {hostname}")

    ip = ipaddress.ip_address(ip_str)
    if not ip.is_global:
        raise UnsafeHostError(f"{hostname} resolves to a non-public address ({ip_str})")

    return ip_str