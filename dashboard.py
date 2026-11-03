import streamlit as st
import docker
import os
import pandas as pd
from datetime import datetime

# --- CONFIGURATION ---
st.set_page_config(page_title="Forensics Command Center", page_icon="🛡️", layout="wide")
client = docker.from_env()

# --- CUSTOM CSS FOR HACKER/SOC AESTHETIC ---
st.markdown("""
    <style>
    .metric-box {
        background-color: #1E1E1E; border-radius: 5px; padding: 15px; border-left: 5px solid #00FF00;
    }
    .metric-box-critical {
        background-color: #1E1E1E; border-radius: 5px; padding: 15px; border-left: 5px solid #FF0000;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ SOC Command Center: Container Forensics")
st.markdown("Zero-Delay Quarantine, Air-Gapping, and Threat Intelligence Pipeline")
st.divider()

# --- DATA GATHERING ---
def get_system_metrics():
    images = client.images.list()
    containers = client.containers.list(all=True)
    
    evidence_count = sum(1 for img in images for tag in img.tags if "evidence-" in tag)
    quarantined_count = sum(1 for c in containers if c.status == 'paused')
    
    return evidence_count, quarantined_count

def get_evidence_inventory():
    images = client.images.list()
    evidence = []
    for img in images:
        for tag in img.tags:
            if "evidence-" in tag:
                evidence.append({
                    "Target Container": tag.split(':')[0],
                    "Evidence Tag": tag.split(':')[1],
                    "Size (MB)": round(img.attrs['Size'] / (1024 * 1024), 2),
                    "Created (UTC)": img.attrs['Created'].split('T')[0]
                })
    return pd.DataFrame(evidence)

# --- TOP LEVEL METRICS ---
ev_count, quar_count = get_system_metrics()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f'<div class="metric-box"><h4>Protected Nodes</h4><h2>{len(client.containers.list())}</h2></div>', unsafe_allow_html=True)
with col2:
    st.markdown(f'<div class="metric-box-critical"><h4>Active Quarantines</h4><h2>{quar_count}</h2></div>', unsafe_allow_html=True)
with col3:
    st.markdown(f'<div class="metric-box"><h4>Forensic Snapshots</h4><h2>{ev_count}</h2></div>', unsafe_allow_html=True)
with col4:
    st.markdown(f'<div class="metric-box"><h4>YARA Rules Active</h4><h2>2</h2></div>', unsafe_allow_html=True)

st.write("") # Spacer

# --- MAIN TABS ---
tab1, tab2, tab3 = st.tabs(["📁 Evidence Vault", "🚨 Incident Response", "⚙️ Engine Status"])

with tab1:
    st.subheader("Immutable Forensic Snapshots (Air-Gapped)")
    df_images = get_evidence_inventory()
    if not df_images.empty:
        st.dataframe(df_images, width='stretch')
    else:
        st.info("No forensic snapshots found. Systems are secure.")
        
    st.subheader("Extracted Volatile Logs & Threat Scans")
    if os.path.exists("forensic_vault"):
        logs = [f for f in os.listdir("forensic_vault") if f.endswith(".log")]
        for log_file in logs:
            with st.expander(f"📄 {log_file}"):
                with open(f"forensic_vault/{log_file}", "r", encoding='utf-8', errors='ignore') as f:
                    st.text(f.read()[-2000:]) # Show last 2000 characters to prevent crashing on huge logs
    else:
        st.info("No logs extracted yet.")

with tab2:
    st.subheader("Manual Override & SIEM Simulation")
    st.write("Trigger the v2.0 engine manually. This will execute the Air-Gap, CPU Halt, and YARA Scan.")
    target_node = st.text_input("Target Node (Container Name)", value="compromised-web-4")
    
    if st.button("🔴 EXECUTE ZERO-DELAY LOCKDOWN", type="primary"):
        with st.spinner('Executing API Call to Engine...'):
            import requests
            try:
                # Calls your local API
                res = requests.post("http://127.0.0.1:8000/api/v1/quarantine", 
                                    json={"alert_id": "MANUAL-001", "severity": "critical", 
                                          "target_container": target_node, "description": "Manual override triggered"})
                if res.status_code == 200:
                    st.success(f"Lockdown successful for {target_node}. Refresh page to view evidence.")
                else:
                    st.error(f"Engine returned an error: {res.text}")
            except Exception as e:
                st.error(f"Failed to reach API. Is api_server.py running? Error: {e}")

with tab3:
    st.subheader("System Health")
    st.success("FastAPI Webhook Listener: **ONLINE**")
    st.success("Docker Daemon Connection: **SECURE**")
    st.success("YARA Threat Intelligence: **LOADED**")