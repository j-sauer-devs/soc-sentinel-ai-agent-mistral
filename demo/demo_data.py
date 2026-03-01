"""
Demo dataset for SOC Sentinel.

Contains 25 pre-built alerts and pre-cached Nettacker results
for a reliable, compelling demo.

Alert mix:
  - 14 obvious false positives / noise (benign scanners, internal IPs)
  - 5 confirmed threats (known malicious IPs)
  - 1 "WOW MOMENT" alert: Triage says Medium, but Nettacker + Threat Hunter
    reveal APT29 C2 infrastructure -> Oversight overrides to Critical
  - 1 Exposed MySQL alert: Triage says Low, Recon reveals high attack surface
    -> Oversight flags RECON_SEVERITY_MISMATCH
  - 4 additional noise / low-risk to push false positive ratio to ~72%
"""

DEMO_ALERTS = [
    # ---- THE WOW MOMENT (APT29 C2 misclassified as Medium) ----
    {
        "id": "ALERT-001",
        "source_ip": "45.33.32.156",
        "alert_type": "Suspicious Outbound Connection",
        "description": (
            "Workstation WS-FIN-042 initiated repeated HTTPS connections to "
            "45.33.32.156 flagged in OTX as APT29 (Cozy Bear) C2 infrastructure. "
            "14 connections over 3 hours, beaconing interval ~12 minutes."
        ),
        "timestamp": "2025-01-15T03:22:11Z",
    },
    # ---- EXPOSED MySQL (Low -> RECON_SEVERITY_MISMATCH) ----
    {
        "id": "ALERT-002",
        "source_ip": "203.0.113.42",
        "alert_type": "Outbound Connection to Unknown Host",
        "description": (
            "Server SRV-DB-03 established outbound connection to 203.0.113.42 "
            "on port 443. Low volume, single connection. Destination not in "
            "any known blocklist."
        ),
        "timestamp": "2025-01-15T03:25:00Z",
    },
    # ---- CONFIRMED THREAT: Tor exit node ----
    {
        "id": "ALERT-003",
        "source_ip": "185.220.101.34",
        "alert_type": "Suspicious Outbound Connection",
        "description": (
            "Endpoint WS-HR-011 connected to 185.220.101.34 over port 443. "
            "IP is a known Tor exit node. Unusual for this endpoint."
        ),
        "timestamp": "2025-01-15T03:28:44Z",
    },
    # ---- CONFIRMED THREAT: Cryptominer ----
    {
        "id": "ALERT-004",
        "source_ip": "91.215.85.12",
        "alert_type": "Suspicious Outbound Connection",
        "description": (
            "Server SRV-COMPUTE-07 initiated connections to 91.215.85.12 on "
            "ports 3333 and 5555. Traffic pattern consistent with Stratum mining "
            "protocol. High CPU usage observed on host."
        ),
        "timestamp": "2025-01-15T03:30:15Z",
    },
    # ---- CONFIRMED THREAT: Malware download ----
    {
        "id": "ALERT-005",
        "source_ip": "10.0.0.88",
        "alert_type": "Malware Download Attempt",
        "description": (
            "Endpoint EDR flagged HTTP GET to http://malware-download.xyz/payload.exe "
            "from host WS-DEV-017. File hash SHA256: "
            "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890. "
            "Connection blocked by proxy but DNS resolution succeeded."
        ),
        "timestamp": "2025-01-15T03:35:01Z",
    },
    # ---- FALSE POSITIVE: Google DNS ----
    {
        "id": "ALERT-006",
        "source_ip": "8.8.8.8",
        "alert_type": "DNS Query Anomaly",
        "description": (
            "High volume of DNS queries to 8.8.8.8 from server SRV-WEB-01. "
            "1,247 queries in 5 minutes. Likely misconfigured resolver."
        ),
        "timestamp": "2025-01-15T03:38:00Z",
    },
    # ---- FALSE POSITIVE: Cloudflare ----
    {
        "id": "ALERT-007",
        "source_ip": "1.1.1.1",
        "alert_type": "DNS Query Anomaly",
        "description": (
            "Spike in DNS queries to Cloudflare resolver 1.1.1.1. "
            "900 queries in 3 minutes from SRV-APP-02. Normal caching behaviour."
        ),
        "timestamp": "2025-01-15T03:40:22Z",
    },
    # ---- FALSE POSITIVE: Benign scanner (Shodan) ----
    {
        "id": "ALERT-008",
        "source_ip": "71.6.135.131",
        "alert_type": "Port Scan Detected",
        "description": (
            "Inbound SYN scan from 71.6.135.131 hitting ports 22, 80, 443, 8080. "
            "Known Shodan scanner IP. Standard internet noise."
        ),
        "timestamp": "2025-01-15T03:42:11Z",
    },
    # ---- FALSE POSITIVE: Internal health check ----
    {
        "id": "ALERT-009",
        "source_ip": "10.0.0.1",
        "alert_type": "Unusual Internal Traffic",
        "description": (
            "Gateway 10.0.0.1 sending ICMP echo to all /24 hosts. "
            "Matches scheduled health check script (cron every 5 min)."
        ),
        "timestamp": "2025-01-15T03:44:00Z",
    },
    # ---- FALSE POSITIVE: Windows Update ----
    {
        "id": "ALERT-010",
        "source_ip": "10.0.0.55",
        "alert_type": "High Bandwidth Usage",
        "description": (
            "WS-ADMIN-003 (10.0.0.55) downloading 2.3 GB from Microsoft CDN "
            "windowsupdate.com. Matches Patch Tuesday schedule."
        ),
        "timestamp": "2025-01-15T03:46:30Z",
    },
    # ---- FALSE POSITIVE: NTP sync ----
    {
        "id": "ALERT-011",
        "source_ip": "10.0.0.10",
        "alert_type": "Unusual Outbound Connection",
        "description": (
            "Domain controller DC-01 (10.0.0.10) sending NTP packets to "
            "time.windows.com. Standard time synchronisation."
        ),
        "timestamp": "2025-01-15T03:48:15Z",
    },
    # ---- FALSE POSITIVE: SIEM agent heartbeat ----
    {
        "id": "ALERT-012",
        "source_ip": "10.0.0.200",
        "alert_type": "Repeated Outbound Connection",
        "description": (
            "SIEM collector 10.0.0.200 sending log data to Splunk cloud "
            "on port 8088 every 30 seconds. Normal forwarder behaviour."
        ),
        "timestamp": "2025-01-15T03:50:00Z",
    },
    # ---- FALSE POSITIVE: CDN traffic ----
    {
        "id": "ALERT-013",
        "source_ip": "104.21.45.67",
        "alert_type": "Connection to Suspicious Domain",
        "description": (
            "Multiple endpoints accessing content via Cloudflare IP 104.21.45.67. "
            "Domain resolves to company marketing site hosted on Cloudflare."
        ),
        "timestamp": "2025-01-15T03:52:44Z",
    },
    # ---- FALSE POSITIVE: Backup traffic ----
    {
        "id": "ALERT-014",
        "source_ip": "10.0.0.30",
        "alert_type": "Large Data Transfer",
        "description": (
            "Backup server 10.0.0.30 transferring 15 GB to AWS S3 bucket. "
            "Matches nightly backup window (03:00-05:00). Authorised traffic."
        ),
        "timestamp": "2025-01-15T03:54:00Z",
    },
    # ---- FALSE POSITIVE: VPN reconnect ----
    {
        "id": "ALERT-015",
        "source_ip": "10.0.0.77",
        "alert_type": "Multiple Authentication Attempts",
        "description": (
            "VPN gateway logged 12 authentication attempts from user jsmith "
            "(10.0.0.77) in 2 minutes. User reported VPN client crashing and "
            "reconnecting. Password correct on all attempts."
        ),
        "timestamp": "2025-01-15T03:56:30Z",
    },
    # ---- CONFIRMED THREAT: Phishing URL ----
    {
        "id": "ALERT-016",
        "source_ip": "198.51.100.23",
        "alert_type": "Phishing URL Detected",
        "description": (
            "Email gateway flagged inbound email with link to "
            "https://login-m1crosoft.com/verify?token=abc123. URL mimics "
            "Microsoft login page. 3 users clicked before block. Hosted on "
            "198.51.100.23."
        ),
        "timestamp": "2025-01-15T03:58:00Z",
    },
    # ---- CONFIRMED THREAT: DNS exfiltration ----
    {
        "id": "ALERT-017",
        "source_ip": "192.0.2.44",
        "alert_type": "DNS Exfiltration Suspected",
        "description": (
            "Endpoint WS-RD-009 sending high-entropy DNS TXT queries to "
            "192.0.2.44 at rate of 200 queries/minute. Subdomain labels "
            "contain base64-encoded strings. Potential data exfiltration."
        ),
        "timestamp": "2025-01-15T04:00:15Z",
    },
    # ---- FALSE POSITIVE: Printer traffic ----
    {
        "id": "ALERT-018",
        "source_ip": "10.0.0.150",
        "alert_type": "Unusual Internal Traffic",
        "description": (
            "Network printer 10.0.0.150 broadcasting mDNS discovery packets "
            "on port 5353. Normal Bonjour/Avahi service advertisement."
        ),
        "timestamp": "2025-01-15T04:02:00Z",
    },
    # ---- FALSE POSITIVE: SCCM software deployment ----
    {
        "id": "ALERT-019",
        "source_ip": "10.0.0.5",
        "alert_type": "Large Data Transfer",
        "description": (
            "SCCM distribution point 10.0.0.5 pushing 4.2 GB software "
            "package to 35 workstations. Matches scheduled deployment "
            "window. Authorised by IT ops team."
        ),
        "timestamp": "2025-01-15T04:04:30Z",
    },
    # ---- FALSE POSITIVE: Load balancer health probe ----
    {
        "id": "ALERT-020",
        "source_ip": "10.0.0.250",
        "alert_type": "Repeated Connection Attempts",
        "description": (
            "AWS ALB health checker 10.0.0.250 sending HTTP GET /health to "
            "12 backend instances every 10 seconds. Expected behaviour for "
            "auto-scaling group."
        ),
        "timestamp": "2025-01-15T04:06:00Z",
    },
    # ---- FALSE POSITIVE: Certificate renewal ----
    {
        "id": "ALERT-021",
        "source_ip": "10.0.0.15",
        "alert_type": "Outbound Connection to Unknown Host",
        "description": (
            "Web server 10.0.0.15 contacting Let's Encrypt ACME endpoint "
            "at acme-v02.api.letsencrypt.org for automated certificate "
            "renewal. Standard certbot operation."
        ),
        "timestamp": "2025-01-15T04:08:22Z",
    },
    # ---- FALSE POSITIVE: Container registry pull ----
    {
        "id": "ALERT-022",
        "source_ip": "10.0.0.60",
        "alert_type": "High Bandwidth Usage",
        "description": (
            "Kubernetes node 10.0.0.60 pulling container images from "
            "ghcr.io during scheduled deployment. 1.8 GB transfer over "
            "5 minutes. Normal CI/CD pipeline activity."
        ),
        "timestamp": "2025-01-15T04:10:00Z",
    },
    # ---- FALSE POSITIVE: Monitoring agent ----
    {
        "id": "ALERT-023",
        "source_ip": "10.0.0.99",
        "alert_type": "Repeated Outbound Connection",
        "description": (
            "Datadog agent on 10.0.0.99 sending metrics to "
            "app.datadoghq.com every 15 seconds. Standard APM telemetry. "
            "Authorised monitoring service."
        ),
        "timestamp": "2025-01-15T04:12:30Z",
    },
    # ---- FALSE POSITIVE: Slack webhook ----
    {
        "id": "ALERT-024",
        "source_ip": "10.0.0.42",
        "alert_type": "Outbound Connection to Unknown Host",
        "description": (
            "Alert bot on 10.0.0.42 posting to hooks.slack.com webhook "
            "URL. Triggered by infrastructure alert. Normal notification "
            "pipeline behaviour."
        ),
        "timestamp": "2025-01-15T04:14:00Z",
    },
    # ---- CONFIRMED THREAT: Lateral movement ----
    {
        "id": "ALERT-025",
        "source_ip": "10.0.0.88",
        "alert_type": "Lateral Movement Detected",
        "description": (
            "Host WS-DEV-017 (10.0.0.88) performing SMB enumeration "
            "against 10.0.0.1, 10.0.0.5, 10.0.0.10 using admin$ share. "
            "Same host flagged in ALERT-005 for malware download. "
            "Possible post-exploitation lateral movement."
        ),
        "timestamp": "2025-01-15T04:16:45Z",
    },
]
