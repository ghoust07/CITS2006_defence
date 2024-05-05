import os
import requests

# Replace with your own API key
# made by oliver for test 2

API_KEY = 'api_key_here'
VT_SCAN_URL = 'https://www.virustotal.com/api/v3/files'

def scan_file(file_path):
    """ Scan a single file with VirusTotal API. """
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            headers = {'x-apikey': API_KEY}
            response = requests.post(VT_SCAN_URL, files=files, headers=headers)
            data = response.json()
            return data
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
        return None

def get_severity(score):
    """ Determine the severity based on the community score. """
    if score == 0:
        return 'Benign'
    elif score < 10:
        return 'Mild'
    elif score < 20:
        return 'Severe'
    else:
        return 'Extreme'

def scan_directories(directories):
    """ Scan all files in specified directories. """
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                print(f"Scanning: {file_path}")
                result = scan_file(file_path)
                if result:
                    # Assuming 'score' key holds the community score
                    score = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    severity = get_severity(score)
                    print(f"File: {file_path} - Severity: {severity}")
                else:
                    print(f"No result for {file_path}")

def main():
    # Specific directories based on the ACL settings for RapidoBank
    directories = [
        "/home/rapidoBank/bankers/diego",
        "/home/rapidoBank/bankers/santiago",
        "/home/rapidoBank/bankers/maria",
        "/home/rapidoBank/shared"
    ]

    # Scan the designated directories
    scan_directories(directories)

if __name__ == "__main__":
    main()
