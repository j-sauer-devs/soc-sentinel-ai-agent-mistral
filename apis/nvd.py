"""
NIST NVD API client.

Searches the National Vulnerability Database for CVEs by keyword.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import os

import requests

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(
    keyword: str,
    api_key: str | None = None,
    cache: dict | None = None,
    max_results: int = 3,
) -> list[dict]:
    """Search NVD for CVEs matching a keyword.

    Returns list of dicts with keys:
        cve_id, description, cvss_score, severity
    Extracts CVSS from cvssMetricV31, falls back to V30, then V2.
    """
    if cache is None:
        cache = {}
    if keyword in cache:
        return cache[keyword]

    key = api_key or os.getenv("NVD_KEY")

    headers = {}
    if key:
        headers["apiKey"] = key

    try:
        resp = requests.get(
            _BASE,
            headers=headers,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()

        results = []
        for vuln in data.get("vulnerabilities", [])[:max_results]:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # Extract description (English preferred)
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]
                    break
            if not desc and descriptions:
                desc = descriptions[0].get("value", "")[:300]

            # Extract CVSS score — try V3.1 → V3.0 → V2
            cvss_score = 0.0
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})

            for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break
            else:
                # Fallback to V2
                v2_list = metrics.get("cvssMetricV2", [])
                if v2_list:
                    cvss_data = v2_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = v2_list[0].get("baseSeverity", "UNKNOWN")

            results.append({
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": cvss_score,
                "severity": severity,
            })

    except Exception as e:
        results = [{"cve_id": "ERROR", "description": str(e), "cvss_score": 0.0, "severity": "UNKNOWN"}]

    cache[keyword] = results
    return results
