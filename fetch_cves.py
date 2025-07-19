import requests
import csv
from datetime import datetime, timedelta, date

KEYWORDS = [
    # Communication / Collaboration
    "Zoom", "Slack", "Microsoft Teams", "Skype", "Google Meet", "Webex",

    # Productivity Suites
    "Microsoft Office", "Word", "Excel", "PowerPoint", "Outlook",
    "Google Workspace", "Docs", "Sheets", "Gmail",

    # File Sharing / Cloud Storage
    "Dropbox", "Box", "Google Drive", "OneDrive",

    # Email Security / Gateways
    "Proofpoint", "Mimecast", "Barracuda", "Cisco Email Security", "Avanan",

    # Endpoint Protection / Antivirus / EDR
    "CrowdStrike", "SentinelOne", "Sophos", "McAfee", "Symantec",
    "Bitdefender", "Trend Micro", "Carbon Black", "ESET",

    # Network Security / Firewalls
    "Palo Alto", "Fortinet", "FortiGate", "Cisco ASA", "Cisco Umbrella",
    "SonicWall", "Check Point", "pfSense", "Akamai",

    # SIEM / Monitoring / Logging
    "Splunk", "Elastic", "Logstash", "Kibana", "Graylog", "IBM QRadar",
    "ArcSight", "Sumo Logic", "LogRhythm", "Google SecOps", "BindPlane",

    # Identity & Access Management
    "Okta", "Duo", "Ping Identity", "Microsoft Active Directory", "Azure AD",
    "LDAP", "CyberArk", "Silverfort", "Reco AI",

    # DLP / SASE / Cloud Security
    "Netskope", "Prisma Cloud", "Zscaler", "Forcepoint", "Lookout",

    # Vulnerability Management / Pentest Tools
    "Rapid7", "Nessus", "Qualys", "Burp Suite", "Metasploit", "Nmap", "OpenVAS",

    # VPN / Remote Access
    "Cisco AnyConnect", "Fortinet VPN", "Palo Alto GlobalProtect", "Pulse Secure", "OpenVPN",

    # Cloud Platforms
    "AWS", "Amazon Web Services", "Azure", "Google Cloud", "GCP",

    # DevOps / CI-CD
    "Jenkins", "GitLab", "GitHub", "Bitbucket", "Docker", "Kubernetes",
    "Ansible", "Terraform", "ArgoCD", "Vault",

    # Web Servers / Reverse Proxies
    "Apache", "Nginx", "IIS", "HAProxy", "Envoy",

    # Databases
    "MySQL", "PostgreSQL", "MongoDB", "Oracle", "SQL Server", "Redis", "ElasticSearch",

    # Backup & Recovery
    "Veeam", "Commvault", "Acronis", "Datto",

    # MDM
    "Jamf", "Intune", "AirWatch", "MobileIron",

    # Ticketing / ITSM
    "ServiceNow", "Jira", "Zendesk", "Freshservice",

    # Other popular or enterprise-used tools
    "Ivanti", "SolarWinds", "Citrix", "TeamViewer", "GoToMeeting"
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

                if any(word.lower() in description.lower() for word in KEYWORDS):
                    cve_metrics = metrics.get("cvssMetricV31")
                    print(cve_metrics)

                    """
                    If v4 exists
                        use that
                    else
                        use v31
                    """


                    # Write Exisiting Data
                    writer.writerow([CVE_ID, published, description])

        print(f"✅ Done writing filtered CVEs to {today}.csv")

    except requests.exceptions.RequestException as req_err:
        print(f"Request error: {req_err}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    fetch_daily_cves()
