#!/usr/bin/env python3
import asyncio, aiohttp, socket, argparse, ssl, json, re, sys, ipaddress, random
from bs4 import BeautifulSoup
from collections import Counter
from datetime import datetime, timezone

# ----------------- CVE CACHE -----------------

CVE_CACHE = {}
MAX_RETRIES = 2


DEFAULT_PORTS = [80, 443, 8080, 8000, 8443]
TIMEOUT = 6
FINDING_TYPES = {
    "security_header_missing": {
        "category": "Informational",
        "confidence": "Contextual",
        "exploitable": False
    },
    "service_cve": {
        "category": "Vulnerability",
        "confidence": "Medium",
        "exploitable": True
    }
}
# ----------------- RISK SCORING -----------------
MAX_CVE_SCORE = 8      # CVE contribution max (0-8)
MAX_HEADER_SCORE = 2   # Missing security headers contribution max (0-2)

# ----------------- SCAN PROFILES -----------------

SCAN_PROFILES = {
    "fast": {
        "probe_concurrency": 10,
        "api_concurrency": 5,
        "delay": (0, 0)
    },
    "balanced": {
        "probe_concurrency": 5,
        "api_concurrency": 3,
        "delay": (0.1, 0.3)
    },
    "stealth": {
        "probe_concurrency": 2,
        "api_concurrency": 1,
        "delay": (0.5, 1.2)
    }
}


CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVEORG_API = "https://cveawg.mitre.org/api/cve/"

SEC_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "A05:2021 Security Misconfiguration"),
    "X-Frame-Options": ("MEDIUM", "A05:2021 Security Misconfiguration"),
    "X-Content-Type-Options": ("LOW", "A05:2021 Security Misconfiguration"),
    "Strict-Transport-Security": ("HIGH", "A02:2021 Cryptographic Failures"),
    "Referrer-Policy": ("LOW", "A01:2021 Broken Access Control"),
}

OWASP_EXPLAIN = {
    "A01:2021 Broken Access Control": "Improper enforcement of user privileges and access rules",
    "A02:2021 Cryptographic Failures": "Weak or missing encryption protections",
    "A05:2021 Security Misconfiguration": "Insecure default settings or missing hardening",
}

# ----------------- VALIDATION -----------------

def is_valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(re.fullmatch(
            r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
            r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}",
            target,
        ))

def resolve_target(target):
    try:
        _, _, ips = socket.gethostbyname_ex(target)
        return sorted(set(ips))
    except socket.gaierror:
        return []

def parse_ports(port_str):
    valid = set()
    invalid = []

    for part in port_str.split(","):
        part = part.strip()

        # Range: 100-200
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                if 1 <= start <= end <= 65535:
                    valid.update(range(start, end + 1))
                else:
                    invalid.append(part)
            except ValueError:
                invalid.append(part)

        # Single port
        else:
            if part.isdigit() and 1 <= int(part) <= 65535:
                valid.add(int(part))
            else:
                invalid.append(part)

    return sorted(valid), invalid


# ----------------- FEEDS -----------------

async def load_kev(session):
    try:
        async with session.get(CISA_KEV_FEED, timeout=15) as r:
            data = await r.json()
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except:
        return set()

def fingerprint(headers):
    server = headers.get("Server", "")
    m = re.search(r"(apache|nginx)[/ ]([\d\.]+)", server.lower())
    return server, (m.group(1) if m else None), (m.group(2) if m else None)
def build_cpe(product, version):
    """
    Minimal CPE 2.3 builder
    """
    if not product or not version:
        return None

    product = product.lower()

    if product == "apache":
        return f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"
    if product == "nginx":
        return f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*"

    return None

def detect_cdn(headers):
    h = {k.lower(): v.lower() for k, v in headers.items()}

    if "cf-ray" in h or "cloudflare" in h.get("server", ""):
        return "Cloudflare"
    if "akamai" in h.get("server", "") or "akamai-grn" in h:
        return "Akamai"
    if "fastly" in h.get("server", "") or "x-served-by" in h:
        return "Fastly"

    return None


# ----------------- TLS FALLBACKS -----------------

def tls_cert_fallback(target, port):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, port))
            return s.getpeercert()
    except:
        return None

def tls_cn_from_cert(cert):
    for item in cert.get("subject", []):
        if item[0][0] == "commonName":
            return item[0][1]
    return None

def tls_san_from_cert(cert):
    sans = []
    for t, v in cert.get("subjectAltName", []):
        if t == "DNS":
            sans.append(v)
    return sans

# ----------------- HTML HEURISTICS -----------------

def html_heuristic(html):
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    signatures = {
        "apache": ["apache", "it works"],
        "nginx": ["nginx", "welcome to nginx"],
    }

    for srv, keys in signatures.items():
        for k in keys:
            if k in title.lower() or k in html.lower():
                return f"{srv.capitalize()} (HTML Heuristic)"
    return None

# ----------------- CVE -----------------

async def fetch_cve_org(session, cve):
    try:
        async with session.get(CVEORG_API + cve, timeout=15) as r:
            d = await r.json()
            meta = d.get("cveMetadata", {})
            return {
                "state": meta.get("state", "UNKNOWN"),
                "assigner": meta.get("assignerShortName", "UNKNOWN"),
                "cve_org_url": f"https://www.cve.org/CVERecord?id={cve}",
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            }
    except:
        return {
            "state": "UNKNOWN",
            "assigner": "UNKNOWN",
            "cve_org_url": f"https://www.cve.org/CVERecord?id={cve}",
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        }

async def fetch_nvd_cves(session, product, version, api_sem):
    if not product or not version:
        return []

    cache_key = f"{product}:{version}"
    if cache_key in CVE_CACHE:
        return CVE_CACHE[cache_key]

    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 5}

    async with api_sem:  # <-- use passed semaphore
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with session.get(NVD_API, params=params, timeout=20) as r:
                    data = await r.json()
                    out = []

                    for v in data.get("vulnerabilities", []):
                        cve = v["cve"]["id"]
                        metrics = v["cve"].get("metrics", {})
                        score = "UNKNOWN"

                        if "cvssMetricV31" in metrics:
                            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV2" in metrics:
                            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                        out.append((cve, score))

                    CVE_CACHE[cache_key] = out
                    return out
            except:
                if attempt == MAX_RETRIES:
                    return []
                await asyncio.sleep(1)

async def fetch_nvd_cves_cpe(session, cpe, api_sem):
    """
    Proper CPE-based CVE enumeration (NVD 2.0 API)
    """
    if not cpe:
        return []

    cache_key = f"CPE::{cpe}"
    if cache_key in CVE_CACHE:
        return CVE_CACHE[cache_key]

    params = {
        "cpeName": cpe,
        "resultsPerPage": 10
    }

    async with api_sem:
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with session.get(NVD_API, params=params, timeout=25) as r:
                    data = await r.json()
                    out = []

                    for v in data.get("vulnerabilities", []):
                        cve = v["cve"]["id"]
                        metrics = v["cve"].get("metrics", {})
                        score = "UNKNOWN"

                        if "cvssMetricV31" in metrics:
                            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV30" in metrics:
                            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV2" in metrics:
                            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                        out.append((cve, score))

                    CVE_CACHE[cache_key] = out
                    return out

            except:
                if attempt == MAX_RETRIES:
                    return []
                await asyncio.sleep(1.5)




# ----------------- ANALYSIS -----------------
# ----------------- CVE CONFIDENCE & FP REDUCTION -----------------

def cpe_specificity_score(cpe):
    """
    Higher score = more specific CPE (fewer wildcards)
    """
    if not cpe:
        return 0.0
    parts = cpe.split(":")
    wildcards = parts.count("*")
    return max(0.0, 1.0 - (wildcards / len(parts)))


def fingerprint_confidence(product, version, server_header):
    score = 0.0

    if product and version:
        score += 0.4   # was 0.5
    if server_header and product in server_header.lower():
        score += 0.2   # was 0.3
    if server_header and ("/" in server_header or "(" in server_header):
        score += 0.1   # was 0.2

    return min(0.6, score)  # HARD CAP

def cve_age_penalty(cve_id):
    try:
        year = int(cve_id.split("-")[1])
        if year < 2015:
            return -0.3
        if year < 2020:
            return -0.15
    except:
        pass
    return 0.0




def cve_confidence_score(
    *,
    cve,
    product,
    version,
    server_header,
    cpe,
    cvss_score,
    kev_hit
):

    """
    Final confidence score (0.0–1.0)
    """
    score = 0.0

    score += fingerprint_confidence(product, version, server_header)
    score += cpe_specificity_score(cpe) * 0.4

    if cvss_score != "UNKNOWN" and float(cvss_score) >= 7:
        score += 0.1

    if kev_hit:
        score += 0.3

    score += cve_age_penalty(cve)
    return round(max(0.0, min(1.0, score)), 2)



def confidence_label(score):
    if score >= 0.85:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"



def analyze_headers(headers, html):
    missing = []
    for h, (r, o) in SEC_HEADERS.items():
        if h not in headers:
            missing.append((h, r, o))
    if html:
        soup = BeautifulSoup(html, "html.parser")
        if soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"}):
            missing = [m for m in missing if m[0] != "Content-Security-Policy"]
    return missing

'''def calculate_risk(weighted_cves, kev, headers):
    score = sum(weighted_cves)
    score += len(kev) * 4
    score += len(headers) * 0.2
    return min(10, round(score, 1))'''


async def probe(session, target, port, sem, profile):
    async with sem:
        dmin, dmax = profile["delay"]
        if dmax > 0:
            await asyncio.sleep(random.uniform(dmin, dmax))
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
        try:
            async with session.get(url, timeout=TIMEOUT) as r:
                return port, True, dict(r.headers), await r.text(errors="ignore")
        except:
            return port, False, None, None



# ----------------- MAIN -----------------

async def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--ports")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument(
    "--mode",
    choices=["passive", "active"],
    default="passive",
    help="Passive = no CVE enumeration, Active = full vulnerability scan"
    )

    p.add_argument(
        "--profile",
        choices=SCAN_PROFILES.keys(),
        default="balanced",
        help="Scan aggressiveness profile"
)

    args = p.parse_args()
    profile = SCAN_PROFILES[args.profile]
    PROBE_SEM = asyncio.Semaphore(profile["probe_concurrency"])
    API_SEM = asyncio.Semaphore(profile["api_concurrency"])

    # --- SCAN MODE MULTIPLIER ---
    if args.mode == "active":
        multiplier = 1.15
    else:
        multiplier = 1.0



    if not is_valid_target(args.target):
        print("\n[!] Invalid target supplied\n")
        sys.exit(1)

    ips = resolve_target(args.target)
    if not ips:
        print("\n[!] DNS resolution failed\n")
        sys.exit(1)

    ports = DEFAULT_PORTS
    if args.ports:
        ports, invalid = parse_ports(args.ports)
        if invalid:
            print(f"[!] Invalid port values ignored: {', '.join(invalid)}")
        if not ports:
            print("\n[!] No valid ports provided\n")
            sys.exit(1)
    # ---- VERBOSE PORT INFO ----
    if args.verbose:
        print(f"[PORTS] Parsed {len(ports)} ports")

    print(f"\n[*] Target  : {args.target}")
    print(f"[*] Resolved: {', '.join(ips)}")
    print(f"[*] Ports   : {ports}")
    # ---- PROFILE TRANSPARENCY (Step 2) ----
    if args.verbose:
        dmin, dmax = profile["delay"]
        print(
            f"[PROFILE] {args.profile} | "
            f"probe_concurrency={profile['probe_concurrency']} | "
            f"api_concurrency={profile['api_concurrency']} | "
            f"delay={dmin}-{dmax}s"
        )
    # ---- MODE TRANSPARENCY (Step 3) ----
    if args.verbose:
        if args.mode == "passive":
            print("[MODE] Passive scan: CVEs based on fingerprints only (no intrusive probes)")
        else:
            print("[MODE] Active scan: CVE enumeration enabled (no exploitation)")

    print(
        "[!] Disclaimer: Informational findings indicate configuration "
        "observations only and do NOT confirm exploitable vulnerabilities.\n"
    )


    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    report_ports = {}
    open_ports, closed_ports = [], []
    all_cves, kev_hits, headers_missing = [], [], []
    weighted_cve_risk = []
    

    owasp = Counter()
    cve_details = {}

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
        kev = await load_kev(session)
        results = await asyncio.gather(
            *[probe(session, args.target, p, PROBE_SEM, profile) for p in ports]
            )


        for port, openp, headers, html in results:
            report_ports[str(port)] = {"open": openp}

            if not openp:
                print(f"[-] {port}/tcp closed")
                closed_ports.append(port)
                continue

            open_ports.append(port)
            print(f"[+] {port}/tcp open")

            server, product, version = fingerprint(headers)
            cdn = detect_cdn(headers)
            cpe = build_cpe(product, version)


            if not server and port in (443, 8443):
                cert = tls_cert_fallback(args.target, port)
                if cert:
                    cn = tls_cn_from_cert(cert)
                    if cn:
                        server = f"TLS CN: {cn}"
                    else:
                        sans = tls_san_from_cert(cert)
                        if sans:
                            server = f"TLS SAN: {', '.join(sans[:2])}"

            if not server:
                heuristic = html_heuristic(html)
                if heuristic:
                    server = heuristic

            if cdn:
                print(f"    Server : {cdn} (CDN detected – origin masked)")
            else:
                print(f"    Server : {server or 'Not disclosed'}")
            if args.verbose:
                if cdn:
                    print("        Banner source: CDN detection")
                elif server and server.startswith("TLS"):
                    print("        Banner source: TLS certificate")
                elif server and "Heuristic" in server:
                    print("        Banner source: HTML heuristic")
                elif server:
                    print("        Banner source: HTTP Server header")
                else:
                    print("        Banner source: Unknown")



            if cdn:
                cves = []
            elif cpe:
                cves = await fetch_nvd_cves_cpe(session, cpe, API_SEM)
            else:
                # fallback to keyword search only if CPE cannot be built
                cves = await fetch_nvd_cves(session, product, version, API_SEM)


            missing = analyze_headers(headers, html)

            report_ports[str(port)].update({
                "server": server,
                "cdn": cdn,
                "cves": [],
                "missing_headers": [
                    {
                        "header": h,
                        "severity": r,
                        "owasp": o,
                        "confidence": FINDING_TYPES["security_header_missing"]["confidence"]
                    }
                    for h, r, o in missing
                ]
})


            if cves:
                print("    CVEs:")
                for cve, score in cves:
                    meta = await fetch_cve_org(session, cve)
                    meta_type = FINDING_TYPES["service_cve"]
                    conf_score = cve_confidence_score(
                        cve=cve,
                        product=product,
                        version=version,
                        server_header=server or "",
                        cpe=cpe,
                        cvss_score=score,
                        kev_hit=(cve in kev),
                    )

                    conf_label = confidence_label(conf_score)
                    print(
                        f"      - {cve} (CVSS {score}) | KEV: {'YES' if cve in kev else 'NO'} | "
                        f"Confidence: {conf_label} ({conf_score})"
                    )
                    #print(f"        [DEBUG] score={conf_score}, label={conf_label}")


                    if conf_label == "Low" and cve not in kev:
                        if args.mode == "passive":
                            print("        ⚠ Likely FP: weak fingerprint or generic CPE match")
                        else:
                            print("        ⚠ Deprioritized in active mode (low confidence)")




                    if args.verbose:
                        print(f"        Source   : NVD (NIST)")
                        print(f"        Status   : {meta['state']} (CVE.org)")
                        print(f"        Assigner : {meta['assigner']}")
                        print(f"        NVD URL  : {meta['nvd_url']}")
                        print(f"        CVE.org  : {meta['cve_org_url']}")
                    # Confidence-weighted CVE risk contribution
                    try:
                        cvss_val = float(score)
                    except:
                        cvss_val = 0.0
                    multiplier = 1.0 if args.mode == "passive" else 1.15
                    weighted = cvss_val * conf_score * multiplier

                    if args.verbose:
                        print(f"        [RISK] CVSS {cvss_val} × confidence {conf_score} = {weighted:.2f}")
                    weighted_cve_risk.append(weighted)
                    # Keep CVE IDs only for reporting (not scoring)
                    threshold = 0.55 if args.mode == "passive" else 0.65
                    if conf_score >= threshold:
                        all_cves.append(cve)



                    report_ports[str(port)]["cves"].append(cve)
                    cve_details[cve] = {
                        **meta,
                        "confidence_score": conf_score,
                        "confidence_level": conf_label,
                        "cvss": score,
                        "kev": cve in kev,
                        "cpe_used": cpe,
                    }

                    if cve in kev:
                        kev_hits.append(cve)
            else:
                print("    CVEs: None")

            if missing:
                print("    Informational Findings (Best-Practice Hardening):")
                for h, r, o in missing:
                    meta = FINDING_TYPES["security_header_missing"]

                    print(f"      - {h} [{r}] ({o}) | "
                    f"{meta['category']} | Not Exploitable"
                    )
                    headers_missing.append(h)
                    owasp[o] += 1
            print()


    # --- NORMALIZE CVE RISK ---
    if weighted_cve_risk:
        cve_risk_score = min(MAX_CVE_SCORE, sum(weighted_cve_risk))  # cap max to 8
    else:
        cve_risk_score = 0.0
    # --- NORMALIZE MISSING HEADERS ---
    header_risk = min(MAX_HEADER_SCORE, len(headers_missing) * 0.25)  # 0-2 scale
    # --- OPTIONAL: KEV BONUS ---
    kev_bonus = min(1, len(kev_hits) * 0.5)  # actively exploited CVEs give small boost
    overall_risk = round(cve_risk_score + header_risk + kev_bonus, 1)
    print(f"Overall Risk Score: {overall_risk}/10\n")
    print("OWASP Mapping (Contextual Taxonomy – Not Proof of Vulnerability):")
    if not owasp:
        print(" No issues detected")
    else:
        for k, v in owasp.items():
            print(f"  {k}: {v} observation(s) — {OWASP_EXPLAIN[k]}")
    if args.verbose:
        print("\nRisk Score Explanation:")
        print(f"  CVE risk       : {round(cve_risk_score, 2)}/8 "
            "(CVSS × confidence, capped)")
        print(f"  Header risk    : {round(header_risk, 2)}/2 "
            "(missing security headers)")
        print(f"  KEV bonus      : {round(kev_bonus, 2)}/1 "
            "(actively exploited CVEs)")
        print("  -----------------------------------")
        print("  Final score    : likelihood-weighted impact (0 = low, 10 = critical)")

    report = {
        "target": args.target,
        "resolved_ips": ips,
        "ports_scanned": ports,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "per_port_results": report_ports,
        "risk_score": overall_risk,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cves": sorted(set(all_cves)),
        "cve_details": cve_details,
        "kev_hits": sorted(set(kev_hits)),
        "missing_headers": headers_missing,
        "owasp_summary": dict(owasp),
    }
    if args.json:
        json.dump(report, open(args.json, "w"), indent=2)
    if args.html:
        open(args.html, "w").write(
            f"<h2>Scan Report for {args.target}</h2>"
            f"<pre>{json.dumps(report, indent=2)}</pre>"
        )

if __name__ == "__main__":
    asyncio.run(main())
