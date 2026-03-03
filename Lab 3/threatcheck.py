import requests
import json
from datetime import datetime
import webbrowser
import os

# ------------------ CONFIGURATION ------------------
API_KEY = '6a0fa6fd91bc11fc5204bc147a83acc41ea86c9616c4162ec40d8bf43f72db6e'  # replace with your VirusTotal API key
BASE_URL = 'https://www.virustotal.com/api/v3'
HEADERS = {"x-apikey": API_KEY}

# ------------------ UTILITY FUNCTIONS ------------------
def format_timestamp(timestamp):
    """Convert UNIX timestamp to human-readable format"""
    if timestamp:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"
print("Status code:", response.status_code)
print(json.dumps(response.json(), indent=4))

def display_stats(stats):
    """Print last_analysis_stats in a readable format"""
    print("\n--- Analysis Stats ---")
    print(f"Harmless:   {stats.get('harmless', 0)}")
    print(f"Malicious:  {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")

def print_json(data):
    """Pretty print JSON data"""
    print(json.dumps(data, indent=4))

def save_and_open_json(filename, data):
    """Save data to JSON file and open it in the default browser"""
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Saved results to {filename}")

    # Open the JSON file in the browser
    path = os.path.abspath(filename)
    webbrowser.open(f"file://{path}")

# ------------------ API SCAN FUNCTIONS ------------------
def scan_hash():
    file_hash = input("Enter File Hash (MD5/SHA1/SHA256): ").strip()
    url = f"{BASE_URL}/files/{file_hash}"

    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        print(f"\nFile Hash: {file_hash}")
        display_stats(attributes.get("last_analysis_stats", {}))
        save_and_open_json(f"{file_hash}_scan.json", data)
    elif response.status_code == 404:
        print(f"File '{file_hash}' not found in VirusTotal database.")
    else:
        print("Error retrieving file data:")
        print_json(response.json())

def scan_ip():
    ip = input("Enter IP Address: ").strip()
    url = f"{BASE_URL}/ip_addresses/{ip}"

    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        print(f"\nIP: {ip}")
        print(f"Country: {attributes.get('country', 'N/A')}")
        print(f"Reputation: {attributes.get('reputation', 'N/A')}")
        display_stats(attributes.get("last_analysis_stats", {}))
        save_and_open_json(f"{ip}_scan.json", data)
    elif response.status_code == 404:
        print(f"IP '{ip}' not found in VirusTotal database.")
    else:
        print("Error retrieving IP data:")
        print_json(response.json())

def scan_domain():
    domain = input("Enter Domain: ").strip()
    url = f"{BASE_URL}/domains/{domain}"

    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        print(f"\nDomain: {domain}")
        print(f"Creation Date: {format_timestamp(attributes.get('creation_date'))}")
        display_stats(attributes.get("last_analysis_stats", {}))
        save_and_open_json(f"{domain}_scan.json", data)
    elif response.status_code == 404:
        print(f"Domain '{domain}' not found in VirusTotal database.")
    else:
        print("Error retrieving domain data:")
        print_json(response.json())

def scan_url():
    url_to_scan = input("Enter URL to scan: ").strip()
    submit_url = f"{BASE_URL}/urls"
    payload = {"url": url_to_scan}

    # Submit URL for scanning
    response = requests.post(submit_url, headers=HEADERS, json=payload)
    if response.status_code in [200, 201]:
        analysis_id = response.json()["data"]["id"]
        print("URL submitted. Fetching analysis...")

        # Fetch analysis results
        analysis_url = f"{BASE_URL}/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=HEADERS)

        if analysis_response.status_code == 200:
            data = analysis_response.json()
            attributes = data["data"]["attributes"]
            display_stats(attributes.get("stats", {}))
            safe_filename = url_to_scan.replace("/", "_").replace(":", "")
            save_and_open_json(f"{safe_filename}_scan.json", data)
        else:
            print("Error retrieving analysis:")
            print_json(analysis_response.json())
    else:
        print("Error submitting URL:")
        print_json(response.json())

# ------------------ MAIN MENU ------------------
def main():
    while True:
        print("\n====== ThreatCheck ======")
        print("1 - Scan IP Address")
        print("2 - Scan Domain")
        print("3 - Scan URL")
        print("4 - Scan File Hash")
        print("5 - Exit")

        choice = input("Select option: ").strip()
        if choice == "1":
            scan_ip()
        elif choice == "2":
            scan_domain()
        elif choice == "3":
            scan_url()
        elif choice == "4":
            scan_hash()
        elif choice == "5":
            print("Exiting ThreatCheck...")
            break
        else:
            print("Invalid selection. Please enter 1-5.")

# ------------------ RUN PROGRAM ------------------
if __name__ == "__main__":
    main()