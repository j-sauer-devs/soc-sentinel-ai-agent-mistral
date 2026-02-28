"""
VirusTotal API client.

Queries VT v3 for IP address reports and domain reports.
Docs: https://docs.virustotal.com/reference/overview
"""

import os

import requests

_BASE = "https://www.virustotal.com/api/v3"


def check_ip(ip: str, api_key: str | None = None, cache: dict | None = None) -> dict:
    """Return VirusTotal analysis for an IP address.

    Returns dict with keys:
        ip, malicious, suspicious, harmless, undetected, reputation,
        as_owner, country
    """
    if cache is None:
        cache = {}
    cache_key = f"ip:{ip}"
    if cache_key in cache:
        return cache[cache_key]

    key = api_key or os.getenv("VIRUSTOTAL_KEY")
    if not key:
        return {"ip": ip, "malicious": -1, "error": "VIRUSTOTAL_KEY not set"}

    try:
        resp = requests.get(
            f"{_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=15,
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "as_owner": attrs.get("as_owner", ""),
            "country": attrs.get("country", ""),
        }
    except Exception as e:
        result = {"ip": ip, "malicious": -1, "error": str(e)}

    cache[cache_key] = result
    return result


def check_domain(domain: str, api_key: str | None = None, cache: dict | None = None) -> dict:
    """Return VirusTotal analysis for a domain."""
    if cache is None:
        cache = {}
    cache_key = f"domain:{domain}"
    if cache_key in cache:
        return cache[cache_key]

    key = api_key or os.getenv("VIRUSTOTAL_KEY")
    if not key:
        return {"domain": domain, "malicious": -1, "error": "VIRUSTOTAL_KEY not set"}

    try:
        resp = requests.get(
            f"{_BASE}/domains/{domain}",
            headers={"x-apikey": key},
            timeout=15,
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar", ""),
        }
    except Exception as e:
        result = {"domain": domain, "malicious": -1, "error": str(e)}

    cache[cache_key] = result
    return result
