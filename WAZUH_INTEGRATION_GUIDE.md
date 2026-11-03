\# Wazuh SIEM Integration Guide



To connect your live Wazuh Manager to the Forensics SaaS API, follow these steps on your Wazuh server.



\### 1. Create the Integration Script

Create the file `/var/ossec/integrations/custom-forensics` and add this code:



```python

\#!/var/ossec/framework/python/bin/python3

import sys, json, requests, re



alert\_file = sys.argv\[1]

with open(alert\_file, 'r') as f:

&#x20;   alert\_data = json.load(f)



level = int(alert\_data.get("rule", {}).get("level", 0))

full\_log = alert\_data.get("full\_log", "")



\# Extract container name dynamically

target\_container = "unknown"

match = re.search(r'container\_name=(\\S+)', full\_log)

if match: target\_container = match.group(1)



payload = {

&#x20;   "alert\_id": alert\_data.get("rule", {}).get("id", "Unknown"),

&#x20;   "severity": "critical" if level >= 10 else "low",

&#x20;   "target\_container": target\_container,

&#x20;   "description": alert\_data.get("rule", {}).get("description", "")

}



\# Replace with the IP of your SaaS Engine

requests.post("http://YOUR\_SAAS\_IP:8000/api/v1/quarantine", json=payload)



2\. Lock File Permissions

sudo chmod 750 /var/ossec/integrations/custom-forensics

sudo chown root:wazuh /var/ossec/integrations/custom-forensics



3\. Update ossec.conf

<integration>

&#x20;   <name>custom-forensics</name>

&#x20;   <level>10</level>

&#x20;   <alert\_format>json</alert\_format>

</integration>

4. Restart Manager

sudo systemctl restart wazuh-manager


