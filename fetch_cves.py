import requests
import json
from datetime import datetime, timedelta, date

# Get Today and Yesterdays Date
today = date.today()
yesterday = today - timedelta(days=1)

def fetch_daily_cves():
    print("Fetching Zero Day Vulnerabilities...")

    # National Vulnerability API Request URL
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={yesterday}T00:00:00.000&pubEndDate={today}T00:00:00.000"

    try:
        # Get Response
        response = requests.get(url)
        
        # Check Response Status Code
        if response.status_code == 200:
            print("Response Success!")
            
            # Prints API Data
            data = response.json()
            print(data)

            

                

        else:
            print("Error Code:", response.status_code)
    
    except Exception as e:
        print(f"An unexpected error occured: {e}")


if __name__ == "__main__":
    fetch_daily_cves()