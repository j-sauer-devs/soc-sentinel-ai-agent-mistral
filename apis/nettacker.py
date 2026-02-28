"""
OWASP Nettacker API wrapper.

Runs Nettacker scans via subprocess and parses JSON output.
Supports DEMO_MODE with pre-cached results for reliable demos.

Docs: https://github.com/OWASP/Nettacker
"""

import json
import os
import subprocess
import time
import uuid

# Module-level cache to avoid scanning the same target+modules twice
_scan_cache: dict = {}

# Demo mode flag — when True, returns pre-cached results
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Demo / pre-cached results
# ---------------------------------------------------------------------------

DEMO_NETTACKER_CACHE = {
    # APT29 C2 IP — THE WOW MOMENT
    "45.33.32.156": {
        "target": "45.33.32.156",
        "scan_modules": ["port_scan", "http_status_scan"],
        "results": {
            "open_ports": [22, 80, 443, 4444, 8080, 8443],
            "services": {
                "22": "OpenSSH 7.4",
                "80": "nginx/1.14.0",
                "443": "nginx/1.14.0",
                "4444": "unknown",
                "8080": "Apache Tomcat/8.5.23",
                "8443": "unknown",
            },
            "vulnerabilities": [
                {"type": "ssl_certificate_expired", "severity": "medium", "detail": "SSL certificate expired 45 days ago"},
                {"type": "clickjacking_vuln", "severity": "low", "detail": "X-Frame-Options header missing"},
                {"type": "outdated_software", "severity": "high", "detail": "Apache Tomcat 8.5.23 has known CVEs (CVE-2020-1938, CVE-2019-0232)"},
                {"type": "outdated_software", "severity": "medium", "detail": "OpenSSH 7.4 is outdated — multiple CVEs including CVE-2018-15473"},
            ],
        },
        "attack_surface_score": 87,
        "scan_duration_seconds": 14.2,
    },
    # Google DNS — benign
    "8.8.8.8": {
        "target": "8.8.8.8",
        "scan_modules": ["port_scan"],
        "results": {
            "open_ports": [53, 443],
            "services": {"53": "dns", "443": "https"},
            "vulnerabilities": [],
        },
        "attack_surface_score": 12,
        "scan_duration_seconds": 3.1,
    },
    # Internal IP — minimal exposure
    "10.0.0.88": {
        "target": "10.0.0.88",
        "scan_modules": ["port_scan"],
        "results": {
            "open_ports": [22, 80, 3389],
            "services": {"22": "OpenSSH 8.9", "80": "Apache/2.4.52", "3389": "RDP"},
            "vulnerabilities": [
                {"type": "rdp_exposed", "severity": "medium", "detail": "RDP (3389) accessible — potential brute-force target"},
            ],
        },
        "attack_surface_score": 35,
        "scan_duration_seconds": 5.8,
    },
    # Exposed MySQL — RECON_SEVERITY_MISMATCH scenario
    "203.0.113.42": {
        "target": "203.0.113.42",
        "scan_modules": ["port_scan", "http_status_scan"],
        "results": {
            "open_ports": [22, 80, 443, 3306, 8080, 9090],
            "services": {
                "22": "OpenSSH 7.2",
                "80": "nginx/1.18.0",
                "443": "nginx/1.18.0",
                "3306": "MySQL 5.7.34",
                "8080": "Apache Tomcat/9.0.31",
                "9090": "Prometheus",
            },
            "vulnerabilities": [
                {"type": "database_exposed", "severity": "critical", "detail": "MySQL 5.7.34 exposed to internet on port 3306"},
                {"type": "admin_panel_exposed", "severity": "high", "detail": "Prometheus admin panel on port 9090 with no auth"},
                {"type": "outdated_software", "severity": "medium", "detail": "OpenSSH 7.2 has multiple known CVEs"},
            ],
        },
        "attack_surface_score": 82,
        "scan_duration_seconds": 11.5,
    },
    # Benign scanner IP
    "71.6.135.131": {
        "target": "71.6.135.131",
        "scan_modules": ["port_scan"],
        "results": {
            "open_ports": [80, 443],
            "services": {"80": "http", "443": "https"},
            "vulnerabilities": [],
        },
        "attack_surface_score": 8,
        "scan_duration_seconds": 2.9,
    },
    # Shodan scanner
    "224.0.0.1": {
        "target": "224.0.0.1",
        "scan_modules": ["port_scan"],
        "results": {
            "open_ports": [],
            "services": {},
            "vulnerabilities": [],
        },
        "attack_surface_score": 0,
        "scan_duration_seconds": 1.2,
    },
    # Suspicious outbound relay
    "185.220.101.34": {
        "target": "185.220.101.34",
        "scan_modules": ["port_scan", "http_status_scan"],
        "results": {
            "open_ports": [22, 80, 443, 9001],
            "services": {
                "22": "OpenSSH 8.2",
                "80": "nginx/1.19.0",
                "443": "nginx/1.19.0",
                "9001": "Tor ORPort",
            },
            "vulnerabilities": [
                {"type": "tor_exit_node", "severity": "high", "detail": "Port 9001 running Tor relay — known exit node"},
            ],
        },
        "attack_surface_score": 55,
        "scan_duration_seconds": 7.3,
    },
    # Phishing domain IP
    "104.21.45.67": {
        "target": "104.21.45.67",
        "scan_modules": ["port_scan", "http_status_scan"],
        "results": {
            "open_ports": [80, 443],
            "services": {"80": "Cloudflare HTTP", "443": "Cloudflare HTTPS"},
            "vulnerabilities": [],
        },
        "attack_surface_score": 15,
        "scan_duration_seconds": 2.1,
    },
    # Cryptominer C2
    "91.215.85.12": {
        "target": "91.215.85.12",
        "scan_modules": ["port_scan", "http_status_scan"],
        "results": {
            "open_ports": [22, 80, 3333, 5555, 8080],
            "services": {
                "22": "OpenSSH 7.6",
                "80": "lighttpd/1.4.55",
                "3333": "Stratum mining",
                "5555": "unknown",
                "8080": "mining pool dashboard",
            },
            "vulnerabilities": [
                {"type": "mining_infrastructure", "severity": "high", "detail": "Ports 3333/5555 consistent with cryptomining pool"},
                {"type": "outdated_software", "severity": "low", "detail": "lighttpd 1.4.55 — minor update available"},
            ],
        },
        "attack_surface_score": 68,
        "scan_duration_seconds": 9.4,
    },
}


def get_demo_nettacker_results(target: str) -> dict:
    """Return cached demo results for a target, or a generic low-risk response."""
    if target in DEMO_NETTACKER_CACHE:
        return DEMO_NETTACKER_CACHE[target]

    # Generic fallback for unknown IPs in demo mode
    return {
        "target": target,
        "scan_modules": ["port_scan"],
        "results": {
            "open_ports": [80, 443],
            "services": {"80": "http", "443": "https"},
            "vulnerabilities": [],
        },
        "attack_surface_score": 10,
        "scan_duration_seconds": 2.0,
    }


# ---------------------------------------------------------------------------
# Live Nettacker scan via subprocess
# ---------------------------------------------------------------------------

class NettackerClient:
    """Runs OWASP Nettacker scans and parses results."""

    def __init__(self, demo_mode: bool | None = None):
        self.demo_mode = demo_mode if demo_mode is not None else DEMO_MODE

    def run_scan(
        self,
        target: str,
        modules: list[str] | None = None,
        timeout: int = 30,
    ) -> dict:
        """
        Run a Nettacker scan on a target.

        Args:
            target: IP address or domain to scan
            modules: List of Nettacker modules (default: ["port_scan"])
            timeout: Max seconds for scan completion

        Returns:
            Structured dict with scan results, or error dict on failure.
        """
        if modules is None:
            modules = ["port_scan"]

        cache_key = f"{target}:{','.join(sorted(modules))}"
        if cache_key in _scan_cache:
            return _scan_cache[cache_key]

        # Demo mode — return pre-cached results
        if self.demo_mode:
            result = get_demo_nettacker_results(target)
            _scan_cache[cache_key] = result
            return result

        # Live scan via subprocess
        output_file = f"/tmp/nettacker_{uuid.uuid4().hex[:8]}.json"
        cmd = [
            "python", "-m", "nettacker",
            "-i", target,
            "-m", ",".join(modules),
            "-o", output_file,
            "--set-timeout", str(timeout),
        ]

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,  # extra buffer
            )

            scan_duration = time.time() - start_time

            # Parse output file
            if os.path.exists(output_file):
                with open(output_file) as f:
                    raw_output = json.load(f)
                os.remove(output_file)  # cleanup
            else:
                raw_output = {}

            # Extract structured results from Nettacker output
            result = self._parse_nettacker_output(target, modules, raw_output, scan_duration)

        except subprocess.TimeoutExpired:
            result = {
                "target": target,
                "error": "scan_timeout",
                "scan_modules": modules,
                "scan_duration_seconds": timeout,
            }
        except FileNotFoundError:
            # Nettacker not installed
            result = {
                "target": target,
                "error": "nettacker_not_installed",
                "scan_modules": modules,
                "scan_duration_seconds": 0,
            }
        except Exception as e:
            result = {
                "target": target,
                "error": str(e),
                "scan_modules": modules,
                "scan_duration_seconds": time.time() - start_time,
            }

        _scan_cache[cache_key] = result
        return result

    def _parse_nettacker_output(
        self, target: str, modules: list[str], raw: dict, duration: float
    ) -> dict:
        """Parse raw Nettacker JSON output into structured results."""
        open_ports = []
        services = {}
        vulns = []

        # Nettacker output varies by module — extract what we can
        for key, value in raw.items():
            if isinstance(value, dict):
                port = value.get("port")
                if port:
                    open_ports.append(int(port))
                    services[str(port)] = value.get("service", "unknown")
                if value.get("vulnerability"):
                    vulns.append({
                        "type": value.get("module", "unknown"),
                        "severity": value.get("severity", "unknown"),
                        "detail": str(value.get("vulnerability", "")),
                    })

        # Calculate attack surface score
        score = self._calculate_attack_surface(open_ports, services, vulns)

        return {
            "target": target,
            "scan_modules": modules,
            "results": {
                "open_ports": sorted(set(open_ports)),
                "services": services,
                "vulnerabilities": vulns,
            },
            "attack_surface_score": score,
            "scan_duration_seconds": round(duration, 1),
            "raw_output": raw,
        }

    @staticmethod
    def _calculate_attack_surface(
        ports: list[int], services: dict, vulns: list[dict]
    ) -> int:
        """Calculate attack surface score 0-100."""
        score = 0

        # Base score from port count
        score += min(len(ports) * 5, 30)

        # C2 / suspicious port bonus
        c2_ports = {4444, 8443, 1337, 9999, 3333, 5555}
        for p in ports:
            if p in c2_ports:
                score += 15

        # Exposed database ports
        db_ports = {3306, 5432, 27017, 6379}
        for p in ports:
            if p in db_ports:
                score += 12

        # Admin panel ports
        admin_ports = {8080, 9090, 8443}
        for p in ports:
            if p in admin_ports:
                score += 5

        # Vulnerability severity bonus
        for v in vulns:
            sev = v.get("severity", "").lower()
            if sev == "critical":
                score += 15
            elif sev == "high":
                score += 10
            elif sev == "medium":
                score += 5

        return min(score, 100)
