# SOC Sentinel AI Agent Cluster

> **Mistral AI Hackathon Submission** — Multi-Agent SOC Triage with OWASP Nettacker Recon + ElevenLabs Voice Briefing

A multi-agent security alert triage system built with [LangGraph](https://github.com/langchain-ai/langgraph), powered by [Mistral AI](https://mistral.ai/) models, enhanced with [OWASP Nettacker](https://github.com/OWASP/Nettacker) active reconnaissance, and voiced by [ElevenLabs](https://elevenlabs.io/) for hands-free incident response.

SOC Sentinel processes batches of security alerts through **7 specialised AI agents** that triage, enrich, investigate, scan, cross-verify, report, and **speak** — combining **passive threat intelligence** (6 APIs) with **active reconnaissance** (OWASP Nettacker) for complete alert investigation.

## Demo

> 📹 **[Watch the demo video](TODO)** — 3-minute walkthrough of SOC Sentinel processing 25 alerts

## Architecture

```
                         +-------------+
                         |  Commander  |
                         +------+------+
                                |
          +----------+----------+----------+-----------+
          |          |          |          |            |
     +----+----+ +---+----+ +--+---+ +----+-----+ +---+------+
     | Triage  | | Threat | |Foren-| | Recon    | | (future) |
     | Officer | | Hunter | |sics  | | Specialist| |          |
     +---------+ +--------+ +------+ | NETTACKER | +----------+
                                      +-----------+
                                           |
                    [port_scan, vuln_scan, service_detect]
                                           |
          +--------------------------------+
          |
   +------+--------+
   | Oversight      |
   | Officer        |
   +------+---------+
          |
   +------+---------+
   | Briefing       |
   | Writer         |
   +----------------+
```

**Commander** routes alerts to all four specialists in parallel via LangGraph's `Send`.

**Triage Officer** classifies alert severity (Critical/High/Medium/Low/Noise) using AbuseIPDB and GreyNoise IP reputation data.

**Threat Hunter** enriches IOCs (IPs, domains, hashes) using AlienVault OTX and VirusTotal. Detects APT/nation-state indicators from OTX pulse names and maps alert types to MITRE ATT&CK techniques.

**Forensics Analyst** reconstructs kill chains and queries NIST NVD for related CVEs when APT activity is suspected.

**Recon Specialist** (NEW) runs OWASP Nettacker scans on alert IPs — port scanning, vulnerability detection, and service identification. Calculates attack surface scores (0-100) and uses Mistral Small to interpret findings.

**Oversight Officer** (powered by Mistral Large) cross-verifies ALL agent findings including Nettacker recon. Detects severity conflicts, hallucinated CVEs, invalid MITRE IDs, and **recon-severity mismatches** — flagging when Triage underestimates threats that Nettacker reveals as high-risk.

**Briefing Writer** produces a final human-readable report with severity breakdown, recon findings, verification conflicts, and assessment.

### Re-Investigation Loop

If the Oversight Officer's confidence score falls below 70 and fewer than 3 iterations have run, the graph loops back to the Commander for re-investigation.

## Security APIs

| API | Purpose | Required |
|-----|---------|----------|
| [AbuseIPDB](https://abuseipdb.com/) | IP reputation scoring (0-100 confidence) | Yes |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat intelligence pulses, APT detection | Yes |
| [VirusTotal](https://www.virustotal.com/) | Malware/IP analysis, detection stats | Yes |
| [NIST NVD](https://nvd.nist.gov/) | CVE lookups with CVSS scores | Yes |
| [GreyNoise](https://www.greynoise.io/) | IP noise/benign classification | Optional |
| [OWASP Nettacker](https://github.com/OWASP/Nettacker) | Active recon: port scanning, vulnerability detection, service identification | Demo mode included |
| [ElevenLabs](https://elevenlabs.io/) | Text-to-speech voice briefing for hands-free SOC operations | Optional |

## LLM

[Mistral AI](https://mistral.ai/) via OpenAI-compatible API at `https://api.mistral.ai/v1`:

| Model | Agents | Purpose |
|-------|--------|---------|
| `mistral-small-latest` | Commander, Triage, Briefing, Recon Specialist | Speed-sensitive tasks |
| `mistral-large-latest` | Threat Hunter, Forensics, Oversight Officer | Reasoning-heavy analysis |

## Project Structure

```
.
+-- apis/                    # Security API clients
|   +-- abuseipdb.py         # IP reputation (confidence 0-100)
|   +-- greynoise.py         # IP classification (graceful stub)
|   +-- elevenlabs_tts.py    # ElevenLabs voice briefing TTS
|   +-- nettacker.py         # OWASP Nettacker wrapper + demo cache
|   +-- nvd.py               # NVD CVE search with CVSS extraction
|   +-- otx.py               # OTX pulse lookups (IP + domain)
|   +-- virustotal.py        # VT v3 analysis (IP + domain)
+-- demo/                    # Demo dataset
|   +-- demo_data.py         # 25 alerts + pre-cached Nettacker results
+-- graph/                   # LangGraph agent system
|   +-- graph.py             # StateGraph wiring + compilation (4 parallel agents)
|   +-- nodes.py             # Agent node implementations (6 agents + Mistral)
|   +-- prompts.py           # Mistral system prompts (all 6 agents)
|   +-- run.py               # Pipeline runner with demo alerts
|   +-- state.py             # SOCState TypedDict schema (with recon_results)
|   +-- utils.py             # extract_reasoning() parser
+-- tests/                   # Integration tests
|   +-- test_full_pipeline.py
+-- app.py                   # Streamlit UI
+-- requirements.txt         # Pinned dependencies
+-- .env.example             # Environment variable template
```

## Setup

### Prerequisites

- Python 3.11+
- Mistral API key
- API keys for AbuseIPDB, OTX, VirusTotal, NVD

### Installation

```bash
git clone https://github.com/j-sauer-devs/soc-sentinel-ai-agent-mistral.git
cd soc-sentinel-ai-agent-mistral
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

```
MISTRAL_API_KEY=your_mistral_key
ABUSEIPDB_KEY=your_key
OTX_KEY=your_key
VIRUSTOTAL_KEY=your_key
NVD_KEY=your_key
GREYNOISE_KEY=          # optional
ELEVENLABS_KEY=         # optional — enables voice briefing
DEMO_MODE=true          # pre-cached Nettacker results for reliable demo
```

### Install Nettacker (Optional)

For live scanning (not required for demo):

```bash
pip install nettacker
# or:
git clone https://github.com/OWASP/Nettacker --depth 1
cd Nettacker && pip install .
```

### Run the Full Pipeline

```bash
python3 -m graph.run
```

### Run the Streamlit UI

```bash
streamlit run app.py
```

### Run Tests

```bash
python3 tests/test_full_pipeline.py
```

## The Demo: "The Wow Moment"

SOC Sentinel processes 25 alerts. Most are noise (Google DNS, internal health checks, container pulls, etc.). But several alerts stand out:

1. **Triage Officer** classifies `45.33.32.156` as **Medium** severity (low AbuseIPDB score)
2. **Threat Hunter** finds APT29 (Cozy Bear) indicators in OTX pulses
3. **Recon Specialist** runs Nettacker and discovers **6 open ports** including:
   - Port 4444 (known C2 channel)
   - Port 8443 (unknown service)
   - Apache Tomcat 8.5.23 with known CVEs
   - Expired SSL certificate
4. **Oversight Officer** catches the conflict:
   - Triage said Medium, but Nettacker found C2 ports AND Threat Hunter found APT29
   - **Overrides to CRITICAL** with full reasoning chain
   - Flags as both `SEVERITY_CONFLICT` and `CORROBORATING_EVIDENCE`

A second alert (`203.0.113.42`) triggers a `RECON_SEVERITY_MISMATCH` — Triage says Low, but Nettacker reveals an exposed MySQL database and admin panel.

## Key Design Decisions

**6 agents, not 5** — SOC Sentinel combines passive intelligence (AbuseIPDB, OTX, VirusTotal, GreyNoise, NVD) with active reconnaissance (OWASP Nettacker). No other approach provides both.

**Agents that audit agents** — The Oversight Officer cross-verifies ALL agent findings. When passive intel corroborates active recon, confidence increases. When they conflict, it flags for human review.

**Rule-based fallback** — The Oversight node includes deterministic conflict detection alongside the LLM, ensuring the demo reliably catches planted misclassifications even if the model's JSON output fails to parse.

**Parallel fan-out with append-only state** — All four specialists run concurrently. LangGraph's `Annotated[list, operator.add]` fields merge results from parallel branches without conflicts.

**Voice briefing for incident response** — ElevenLabs TTS converts the final security briefing into audio, enabling hands-free SOC operations during active incidents when analysts can't look at screens.

**Graceful degradation** — Missing API keys return stub responses instead of crashing. Demo mode provides pre-cached Nettacker results for reliable offline demos.

## License

MIT
