import requests
import csv
import json
import re
from datetime import datetime, timedelta, date

KEYWORDS = [
    # Critical Web Browsers (Massive attack surface)
    "Google Chrome", "Microsoft Edge", "Mozilla Firefox",

    # Core Microsoft Infrastructure
    "Microsoft Windows", "Windows Server", "Microsoft Office", "Microsoft Outlook",
    "Microsoft Active Directory", "Azure Active Directory", "Microsoft Exchange",
    "Windows Defender", "Microsoft Defender",

    # Linux Distributions & Operating Systems
    "Ubuntu", "Debian", "Red Hat", "Kali Linux",

    # Endpoint Protection / Antivirus / EDR
    "CrowdStrike", "SentinelOne", "Bitdefender",

    # Network Security / Firewalls
    "Palo Alto", "Palo Alto Networks", "Fortinet", "FortiGate", "Cisco Umbrella",
    "Check Point", "Akamai", "Cloudflare",

    # SIEM / Monitoring / Logging
    "Google Chronicle", "Google SecOps",

    # Identity & Access Management
    "Okta", "Duo Security", "CyberArk", "Silverfort",

    # DLP / SASE / Cloud Security
    "Netskope", "Prisma Cloud", "Zscaler",

    # Email Security / Gateways
    "Mimecast", "Avanan",

    # Vulnerability Management / Pentest Tools
    "Rapid7",

    # VPN / Remote Access
    "Cisco AnyConnect", "FortiClient",

    # Critical Cloud Platforms
    "AWS", "Amazon Web Services", "Microsoft Azure", "Google Cloud", "Oracle Cloud",

    # Core Network Infrastructure
    "Cisco", "VMware", "Apache HTTP",

    # Essential Databases
    "Microsoft SQL Server", "Oracle Database", "MySQL", "PostgreSQL",

    # Key Enterprise Applications
    "ServiceNow", "SharePoint",

    # Critical Programming Runtimes
    "Java", ".NET", "Python",
]

def fetch_daily_cves():
    now = datetime.utcnow()
    yesterday = now - timedelta(days=1)
    today = date.today()

    pub_start = yesterday.isoformat(timespec='milliseconds') + "Z"
    pub_end = now.isoformat(timespec='milliseconds') + "Z"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start}&pubEndDate={pub_end}"
    print(f"Fetching CVEs from {pub_start} to {pub_end}")

    try:
        response = requests.get(url)
        response.raise_for_status()

        data = response.json()
        
        print(f"Total CVEs found: {len(data.get('vulnerabilities', []))}")

        with open(f"{today}_cve.csv", "w", newline="", encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["CVE ID", "Published Date", "CVSS", "Severity", "Description", "Affected Products", "Exploitability Score", "References"])

            for cve_data in data.get("vulnerabilities", []):
                cve = cve_data.get("cve", {})
                metrics = cve.get("metrics")
                CVE_ID = cve.get("id", "N/A")
                published = cve.get("published", "N/A")

                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                print(f"Processing {CVE_ID}: {description[:100]}...")  # Debug output

                for word in KEYWORDS:
                    # Use regex for exact word matching (case-insensitive)
                    # \b ensures word boundaries, so "Go" won't match "goform"
                    pattern = r'\b' + re.escape(word) + r'\b'
                    if re.search(pattern, description, re.IGNORECASE):
                        print(f"✅ MATCH found for '{word}' in {CVE_ID}")

                        affected_prod = word

                        # Get Metric Version (check if metrics exists)
                        exploitability_score = "N/A"
                        CVSS_score = "N/A"
                        severity = "N/A"
                        
                        if metrics:
                            cvss_metric = metrics.get("cvssMetricV31", [])
                            
                            # Get Exploitability Score & CVSS Score
                            for metric_data in cvss_metric:
                                exploitability_score = metric_data.get('exploitabilityScore', 'N/A')
                                cvss_data = metric_data.get('cvssData', {})
                                CVSS_score = cvss_data.get('baseScore', 'N/A')
                                severity = cvss_data.get('baseSeverity', 'N/A')
                                break

                        # Get references
                        references = cve.get("references", [])
                        ref_urls = []
                        for ref in references:
                            if ref.get("url"):
                                ref_urls.append(ref["url"])

                        # Auto-Fit Excel/Sheets Row Height for multiline references
                        references_str = "\n".join(ref_urls) if ref_urls else "N/A"

                        # Write complete data matching CSV header
                        writer.writerow([CVE_ID, published, CVSS_score, severity, description, affected_prod, exploitability_score, references_str])
                        break

        print(f"✅ Done writing filtered CVEs to {today}.csv")

    except requests.exceptions.RequestException as req_err:
        print(f"Request error: {req_err}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    fetch_daily_cves()
