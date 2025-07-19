import requests
import csv
import json
import re
from datetime import datetime, timedelta, date

KEYWORDS = [
    # Communication / Collaboration
    "Zoom", "Slack", "Microsoft Teams", "Skype", "Google Meet", "Webex", "Discord",

    # Productivity Suites (balanced specificity)
    "Microsoft Office", "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Microsoft Outlook",
    "Google Workspace", "Google Docs", "Google Sheets", "Gmail",

    # File Sharing / Cloud Storage
    "Dropbox", "Box.com", "Google Drive", "OneDrive", "SharePoint",

    # Email Security / Gateways
    "Proofpoint", "Mimecast", "Barracuda", "Cisco Email Security", "Avanan",

    # Endpoint Protection / Antivirus / EDR
    "CrowdStrike", "CrowdStrike Falcon", "SentinelOne", "Sophos", "McAfee", "Symantec",
    "Bitdefender", "Trend Micro", "Carbon Black", "ESET NOD32", "ESET Internet Security", "ESET Endpoint",

    # Network Security / Firewalls
    "Palo Alto", "Palo Alto Networks", "Fortinet", "FortiGate", "Cisco ASA", "Cisco Umbrella",
    "SonicWall", "Check Point", "pfSense", "Akamai",

    # SIEM / Monitoring / Logging
    "Splunk", "Elasticsearch", "Logstash", "Kibana", "Graylog", "IBM QRadar",
    "ArcSight", "Sumo Logic", "LogRhythm", "Google Chronicle", "BindPlane",

    # Identity & Access Management
    "Okta", "Duo Security", "Ping Identity", "Microsoft Active Directory", "Azure Active Directory",
    "CyberArk", "Silverfort",

    # DLP / SASE / Cloud Security
    "Netskope", "Prisma Cloud", "Zscaler", "Forcepoint", "Lookout",

    # Vulnerability Management / Pentest Tools
    "Rapid7", "Nessus", "Tenable", "Qualys", "Burp Suite", "Metasploit", "Nmap", "OpenVAS",

    # VPN / Remote Access
    "Cisco AnyConnect", "FortiClient", "GlobalProtect", "Pulse Secure", "OpenVPN",

    # Cloud Platforms
    "AWS", "Amazon Web Services", "Microsoft Azure", "Google Cloud", "Oracle Cloud",

    # DevOps / CI-CD
    "Jenkins", "GitLab", "GitHub", "Bitbucket", "Docker", "Kubernetes",
    "Ansible", "Terraform", "ArgoCD", "HashiCorp Vault",

    # Programming Languages & Runtimes
    "Java", "JavaScript", "Python", "Node.js", "PHP", "Ruby", "Golang", "Rust",
    "C++", "C#", ".NET", "TypeScript", "Swift", "Kotlin", "Scala",

    # Git Libraries & Version Control
    "GitHub Actions", "GitLab CI", "libgit2", "JGit", "GitPython",
    "Subversion", "SVN", "Mercurial",

    # Web Frameworks & Libraries
    "React", "Angular", "Vue.js", "Express.js", "Django", "Flask", "Spring Boot",
    "Laravel", "Ruby on Rails", "ASP.NET", "jQuery", "Bootstrap",

    # Package Managers & Build Tools
    "npm", "Yarn", "Maven", "Gradle", "pip", "Composer", "NuGet", "RubyGems",
    "Webpack", "Babel", "Vite", "Rollup",

    # Development Tools & IDEs
    "Visual Studio Code", "IntelliJ IDEA", "Eclipse", "Xcode", "Android Studio",
    "Sublime Text", "Atom", "Vim", "Emacs",

    # Web Servers / Reverse Proxies
    "Apache HTTP", "Nginx", "Microsoft IIS", "HAProxy",

    # Databases
    "MySQL", "PostgreSQL", "MongoDB", "Oracle Database", "SQL Server", "Redis", "Elasticsearch",

    # Backup & Recovery
    "Veeam", "Commvault", "Acronis", "Datto",

    # MDM
    "Jamf", "Microsoft Intune", "AirWatch", "MobileIron",

    # Ticketing / ITSM
    "ServiceNow", "Jira", "Zendesk", "Freshservice",

    # Other popular enterprise tools
    "Ivanti", "SolarWinds", "Citrix", "TeamViewer"
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

                for word in KEYWORDS:
                    # Use regex for exact word matching (case-insensitive)
                    # \b ensures word boundaries, so "Go" won't match "goform"
                    pattern = r'\b' + re.escape(word) + r'\b'
                    if re.search(pattern, description, re.IGNORECASE):

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
