import requests
import json
import time

def simulate_wazuh_alert(target_container: str):
    """Simulates a critical alert webhook from a Wazuh Manager."""
    
    # The URL of your local FastAPI webhook listener
    api_url = "http://127.0.0.1:8000/api/v1/quarantine"
    
    # The exact payload structure your API expects
    payload = {
        "alert_id": "Wazuh-100200",
        "severity": "critical",
        "target_container": target_container,
        "description": "Reverse shell execution detected via netcat"
    }

    print(f"[*] SIEM Simulator: High-severity threat detected in '{target_container}'.")
    print(f"[*] SIEM Simulator: Firing automated webhook to SaaS engine at {api_url}...")
    time.sleep(1) # Brief pause for effect
    
    try:
        response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
        print(f"\n[+] Webhook fired successfully! API HTTP Status: {response.status_code}")
        print(f"[+] API Response Data:\n{json.dumps(response.json(), indent=2)}")
    except requests.exceptions.ConnectionError:
        print("\n[-] Connection Failed: Ensure api_server.py is running on port 8000.")

if __name__ == "__main__":
    print("=== Wazuh Webhook Simulator ===")
    
    # We will target a fresh container for this test
    TARGET = "compromised-web-2"
    simulate_wazuh_alert(TARGET)