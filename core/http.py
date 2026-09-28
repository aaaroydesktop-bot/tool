"""Small shared HTTP layer: one session, sane defaults, no SSL warnings."""

from __future__ import annotations

import json

from . import __version__

USER_AGENT = f"NetScan/{__version__} (+https://termux.dev)"

DEFAULT_TIMEOUT = 8
DEFAULT_HEADERS = {"User-Agent": USER_AGENT, "Accept": "*/*"}

_session = None
_warnings_off = False


def _silence_ssl_warnings() -> None:
    """Import urllib3 only when HTTP is actually used."""
    global _warnings_off
    if _warnings_off:
        return
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:  # pragma: no cover - urllib3 ships with requests
        pass
    _warnings_off = True


def session():
    """Lazily built requests session shared by every module."""
    global _session
    if _session is None:
        _silence_ssl_warnings()
        import requests

        _session = requests.Session()
        _session.headers.update(DEFAULT_HEADERS)
    return _session


def get(url: str, timeout: float = DEFAULT_TIMEOUT, **kwargs):
    kwargs.setdefault("allow_redirects", True)
    return session().get(url, timeout=timeout, **kwargs)


def get_json(url: str, timeout: float = DEFAULT_TIMEOUT, **kwargs):
    kwargs.setdefault("verify", False)
    try:
        return get(url, timeout=timeout, **kwargs).json()
    except (ValueError, json.JSONDecodeError):
        return None


def head(url: str, timeout: float = DEFAULT_TIMEOUT, **kwargs):
    return session().head(url, timeout=timeout, **kwargs)


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("empty URL")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def public_ip(timeout: float = DEFAULT_TIMEOUT) -> str | None:
    """Ask a few providers for this device's public IP."""
    for url, extract in (
        ("https://api.ipify.org?format=json", lambda d: d.get("ip")),
        ("https://ifconfig.co/json", lambda d: d.get("ip")),
    ):
        try:
            data = get_json(url, timeout=timeout)
            if data:
                value = extract(data)
                if value:
                    return value
        except Exception:
            continue
    return None
