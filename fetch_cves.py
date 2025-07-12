import requests
import json
from datetime import datetime, timedelta, date
import csv

# Get today and yesterdays date
today = date.today()
yesterday = today - timedelta(days=1)

def fetch_daily_cves():
    print("Fetching Zero Day Vulnerabilities...")

    # National vulnerability API request URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={yesterday}T00:00:00.000&pubEndDate={today}T00:00:00.000"

    try:
        # Get response
        response = requests.get(url)
        
        # Check response status code
        if response.status_code == 200:
            print("Response Success!")
            
            # Uses JSON data and gets all the vulnerabilities 
            data = response.json()
            cve = data.get("vulnerabilities", [])
            
            # Print formatted CVE JSON data
            print(json.dumps(cve, indent=2))

            with open("daily_cve.csv", "w") as file:

                # Create writer for the CSV file and add header
                writer = csv.writer(file)
                writer.writerow(["CSV", "Description"])
                
                # Testing to see if the ID's print
                for vul in cve:
                    print(vul['cve']['id'])


        else:
            print("Error Code:", response.status_code)
    
    except Exception as e:
        print(f"An unexpected error occured: {e}")


if __name__ == "__main__":
    fetch_daily_cves()