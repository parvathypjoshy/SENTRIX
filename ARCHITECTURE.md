## 🔎 Detection & Intelligence Architecture

SENTRIX employs a layered analysis architecture that correlates multiple weak signals into confidence-weighted findings, rather than relying on single indicators or intrusive testing.

Network Control & Request Governance

All network operations in SENTRIX are governed by strict concurrency and rate-control mechanisms to ensure safe, non-disruptive scanning.

Includes:

Asynchronous request scheduling with bounded concurrency

Profile-based request pacing (fast / balanced / stealth)

Rate-aware access to external intelligence APIs (NVD, CVE.org)

Automatic retry and timeout handling

Purpose:
Maintain ethical, production-safe scanning while preserving accuracy and performance.

## 1. Service Fingerprinting

Identifies exposed services using multiple fallback mechanisms:

HTTP Server header parsing

TLS certificate CN / SAN extraction

HTML heuristic fingerprinting (welcome pages, embedded signatures)

CDN detection to prevent origin misattribution

Purpose:
Establish the strongest possible service identity before vulnerability correlation.

## 2. CPE Construction Engine

Builds minimal, version-aware CPE 2.3 identifiers from observed service fingerprints.

Supported services include:

Apache HTTP Server

Nginx

Includes:

Vendor and product normalization

Version-aware specificity scoring

Wildcard impact reduction

Purpose:
Enable accurate CVE enumeration while minimizing false positives.

## 3. CVE Enumeration & Enrichment

Performs vulnerability discovery using authoritative intelligence sources:

NVD 2.0 API (keyword-based and CPE-based queries)

CVE.org metadata enrichment

CVSS v3.x / v2 parsing

Automatic caching and rate-aware API access to respect upstream limits

Purpose:
Retrieve trustworthy vulnerability data without aggressive probing.

## 4. CISA KEV Correlation

Cross-references discovered CVEs with the CISA Known Exploited Vulnerabilities (KEV) catalog.

Adds:

Exploitation likelihood boost

Prioritization context for active threats

Purpose:
Distinguish theoretical vulnerabilities from those actively exploited in the wild.

## 5. Confidence Scoring & False-Positive Reduction

Each CVE is assigned a 0.0–1.0 confidence score derived from:

Fingerprint strength

CPE specificity

CVSS severity

KEV presence

CVE age penalty

Confidence levels:

High

Medium

Low

Purpose:
Reduce noise and prevent misleading vulnerability claims.

## 6. Security Header Analysis (Best-Practice Hardening)

Detects missing HTTP security headers:

Content-Security-Policy

Strict-Transport-Security (HSTS)

X-Frame-Options

X-Content-Type-Options

Referrer-Policy

Mapped contextually to:

OWASP Top 10 (non-exploitative taxonomy)

Purpose:
Provide configuration hygiene insights without claiming exploitation.

## 7. Risk Scoring Engine

Computes a final 0–10 exposure score using:

Confidence-weighted CVE impact

Configuration weakness contribution

KEV exploitation bonus

Supports:

Passive mode (observation-only)

Active mode (full enumeration, still non-intrusive)

Purpose:
Produce a realistic, decision-oriented risk metric.
