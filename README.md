# Daily CVE Fetcher

This Python script fetches the latest CVEs from the National Vulnerability Database (NVD), filters them based on vulnerable software keywords, and saves selected information to a CSV file named after today's date.

## Features

- Pulls CVEs from the past 24 hours
- Filters CVEs based on **software keywords**
- Extracts and saves:
  - CVE ID
  - Description
  - CVSS Score (v3.1 preferred)
  - Exploitability Score
  - Affected Software

## Output

- Results are saved in a CSV file named after the current date, e.g., `2025-07-19.csv`

## Requirements

- Python 3
- `requests` library