# SENTRIX

### Confidence-Based Web Exposure Intelligence Scanner
SENTRIX is an asynchronous web security analysis tool that correlates service fingerprinting, CPE-aware CVE enumeration, CISA Known Exploited Vulnerabilities (KEV), and configuration weaknesses to produce confidence-weighted risk assessments instead of noisy vulnerability lists.

It focuses on signal quality, false-positive reduction, and transparency, making it suitable for security researchers, blue teams, and bug bounty workflows.

## ✨ Core Capabilities
- Async multi-port probing with profile-based rate control

- Intelligent service fingerprinting:

- HTTP Server headers

- TLS certificate CN / SAN fallback

- HTML heuristic fingerprinting

- CPE-based CVE enumeration using NVD 2.0 API & Rate Limiting

- CVE.org metadata enrichment

- CISA KEV feed correlation (real-world exploitation context)

- Semaphore-based rate limiting for both network probes and external APIs

- Profile-driven concurrency caps
  
- Randomized jitter delays (stealth mode)
  
- Shared API semaphore to respect NVD 2.0 rate limits

- Confidence scoring to reduce false positives

- Passive vs Active scan modes (explicit and transparent)

- OWASP Top 10 mapping as contextual taxonomy (not proof)

- JSON and HTML report generation
  
## 🧠 Design Philosophy
SENTRIX does not exploit vulnerabilities.

Instead, it answers:

“How likely is this service actually affected?”

All findings are:
- Evidence-backed

- Confidence-rated

- Non-destructive

- Safe for scoped environments
OWASP mappings are provided for context, not as vulnerability confirmation.

Confidence scores are intentionally hard-capped to prevent score inflation.
Weak or ambiguous fingerprints cannot produce high-risk findings, even when
high-severity CVEs exist.


## 🚀 Installation
git clone https://github.com/parvathypjoshy/SENTRIX.git

cd SENTRIX
pip install .
sentrix example.com

or

git clone https://github.com/parvathypjoshy/SENTRIX.git

python3 sentrix.py example.com

## Requirements
- Python 3.8+
- Internet access for NVD / KEV feeds

## 🧪 Usage Examples

## Default balanced scan
python sentrix.py example.com

### Stealth profile (low noise)
python sentrix.py example.com --profile stealth

### Active intelligence mode
python sentrix.py example.com --mode active

### Custom ports
python sentrix.py example.com --ports 80,443,8000,8080,8443
### Range of Ports
python sentrix.py example.com --ports 1-65535

### JSON report
python sentrix.py example.com --json report.json

### HTML report
python sentrix.py example.com --html report.html

### Verbose transparency mode
python sentrix.py example.com --verbose

## ⚙️ Scan Profiles
| Profile  | Probe Concurrency | API Concurrency | Delay      | Use Case                      |
| -------- | ----------------- | --------------- | ---------- | ----------------------------- |
| fast     | High              | Medium          | None       | Labs / internal               |
| balanced | Medium            | Medium          | Low        | Default                       |
| stealth  | Low               | Low             | Randomized | Bug bounty / sensitive scopes |

SENTRIX uses layered intelligence analysis to correlate multiple weak signals into
confidence-weighted security findings — without intrusive exploitation.

### 1. Service Fingerprinting
Multi-source service identification using HTTP headers, TLS certificates,
HTML heuristics, and CDN detection to ensure accurate attribution.

CDN detection suppresses origin CVE attribution when responses are served
by edge providers (e.g., Cloudflare, Akamai), preventing false positives.

### 2. CPE Construction Engine
Generates minimal CPE 2.3 identifiers from observed fingerprints with
vendor normalization and version-aware specificity scoring.

### 3. CVE Enumeration & Enrichment
Retrieves authoritative vulnerability data from NVD and CVE.org with
CVSS parsing and intelligent caching.

### 4. CISA KEV Correlation
Prioritizes vulnerabilities actively exploited in the wild using
CISA Known Exploited Vulnerabilities data.

### 5. Rate Limiting & Scan Safety

SENTRIX uses explicit, semaphore-based rate limiting to ensure safe and
predictable scanning behavior.
This design minimizes target impact, avoids API throttling, and supports
responsible use in bug bounty and production environments.

### 6. Confidence Scoring
Assigns probabilistic confidence (0.0–1.0) to each CVE using fingerprint
strength, CPE accuracy, CVSS severity, and KEV presence.

### 7. Security Header Analysis
Identifies missing HTTP security headers and maps findings to
OWASP Top 10 for configuration hygiene insights.

### 8. Risk Scoring Engine
Produces a final 0–10 exposure score using confidence-weighted CVEs,
configuration weaknesses, and exploitation likelihood.

### 🛠️ Architecture

sentrix.py
│

├── Validation & Input Handling
│

├── Network Probing Engine (async)
│

├── Fingerprinting Layer

│   ├── Header-based identification

│   ├── TLS certificate analysis

│   └── HTML heuristic fingerprinting

│
├── CPE Construction Engine

│
├── CVE Enumeration Engine

│   ├── NVD keyword-based search

│   └── NVD CPE-based search

│
├── CISA KEV Correlation

│
├── Confidence & Risk Scoring

│
├── OWASP Contextual Mapping

│
└── Reporting

  ├── JSON (machine-readable)

  └── HTML (human-readable)
    

Produces a final 0–10 exposure score using confidence-weighted CVEs,
configuration weaknesses, and exploitation likelihood.
### 📊 Risk Scoring Model

Final score (0–10) is calculated using:
- CVE Risk
  CVSS × confidence score (capped)

- Configuration Risk
Missing security headers

- KEV Bonus
Actively exploited CVEs

This produces a likelihood-weighted impact score, not inflated severity.
### Output Structure

## 📊 Analysis Output & Reporting

SENTRIX generates structured, confidence-weighted reports designed for
triage, automation, and long-term risk tracking.

### 📁 Report Artifacts

A standard scan produces the following outputs:

results/
├── summary.json          # Overall exposure score and scan metadata
├── findings.json         # All correlated vulnerability findings
├── kev_findings.json     # Actively exploited CVEs (CISA KEV)
└── report.html           # Human-readable risk report

---
### 🕵️‍♂️ PASSIVE VS ⚡ ACTIVE
Passive mode avoids external CVE enumeration entirely and relies only on
observed fingerprints. Active mode enables CVE correlation without any
exploitation or intrusive requests.

### 🛡️ Safety & Ethics

- No payload injection

- No exploitation

- Read-only HTTP analysis

- CDN-aware logic to avoid false attribution

- Designed for authorized targets only
### 📄 License

MIT License
### ⚠️ Disclaimer

SENTRIX is intended for authorized security testing and research only.
The authors assume no liability for misuse.

### 🧾 Finding Record Schema

Each finding represents a **correlated vulnerability**, not a single signal.
Multiple observations are combined into a confidence-weighted result.

| Field              | Description |
|-------------------|-------------|
| `cve`             | CVE identifier |
| `service`         | Identified service/product |
| `port`            | Network port |
| `cvss`            | CVSS base score |
| `confidence_score`| Aggregated confidence (0.0 – 1.0) |
| `confidence_level`| High / Medium / Low |
| `kev`             | Present in CISA KEV catalog |
| `cpe_used`        | Final CPE used for correlation |
| `source`          | Authoritative references |

---

### 🔎 Example Finding

```json
{
  "cve": "CVE-2021-41773",
  "service": "Apache HTTP Server",
  "port": 80,
  "cvss": 7.5,
  "confidence_score": 0.82,
  "confidence_level": "High",
  "kev": true,
  "cpe_used": "cpe:2.3:a:apache:http_server:2.4.49:::::::*",
  "source": {
    "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    "cve_org": "https://www.cve.org/CVERecord?id=CVE-2021-41773"
  }
}
