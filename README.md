\# 🛡️ Cloud Container Forensics Platform (Zero-Delay Agent)



An automated, zero-touch incident response engine designed to solve the ephemeral evidence problem in containerized cloud environments. 



When a SIEM detects a high-severity threat (like a reverse shell), the orchestrator often destroys the compromised container, taking the volatile memory and logs with it. This lightweight Python agent acts as a webhook listener, executing a programmatic lock-down in milliseconds to preserve the chain of custody before the container is lost.



\## Core Capabilities

\* Zero-Delay Network Air-Gapping: Instantly severs the container from Docker bridge networks, killing attacker reverse shells without destroying active RAM.

\* CPU Execution Halting: Freezes the container state perfectly for post-incident memory analysis.

\* Automated Threat Intelligence: Mounts the extracted file system and runs YARA signature scans to instantly categorize the malware (e.g., Cryptominers, Web Shells).

\* Immutable Evidence Vault: Dumps volatile logs and commits the frozen container to a new, permanent Docker image tag.



\## Architecture

The engine runs a FastAPI webhook listener that accepts JSON payloads directly from SIEMs like Wazuh or Splunk. The backend logic interacts directly with the host's Docker socket and YARA engine, while the SOC Command Center is visualized via a decoupled Streamlit dashboard.



\## Quickstart (Local Staging)



1\. Clone \& Install

&#x20;  ```bash

&#x20;  git clone \ https://github.com/karthikdorapally/cloud-forensics-saas.git https://github.com/karthikdorapally/cloud-forensics-saas.git

&#x20;  cd cloud-forensics-saas

&#x20;  python3 -m venv venv

&#x20;  source venv/bin/activate

&#x20;  pip install -r requirements.txt

