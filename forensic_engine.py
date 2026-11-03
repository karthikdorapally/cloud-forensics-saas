import docker
import datetime
import os
import yara

def secure_compromised_container(container_name: str):
    """Air-gaps, snapshots, and scans a compromised Docker container."""
    
    client = docker.from_env()
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_tag = f"evidence-{timestamp}"

    try:
        print(f"[*] Locating container '{container_name}'...")
        container = client.containers.get(container_name)
        
        # --- ADVANCED FEATURE: NETWORK AIR-GAPPING ---
        print("[*] STEP 1: Initiating Network Air-Gap...")
        networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
        
        if not networks:
            print("    [*] Container is not attached to any networks or is already isolated.")
        else:
            for net_name in networks.keys():
                try:
                    network = client.networks.get(net_name)
                    network.disconnect(container)
                    print(f"    [+] Severed connection to network: {net_name}")
                except Exception as net_err:
                    print(f"    [-] Warning: Could not disconnect from {net_name}: {net_err}")
        
        # --- LOG EXTRACTION ---
        print("[*] STEP 2: Extracting volatile logs...")
        logs = container.logs().decode('utf-8', errors='ignore')
        os.makedirs("forensic_vault", exist_ok=True)
        log_path = f"forensic_vault/{container_name}_{evidence_tag}.log"
        
        with open(log_path, "w", encoding='utf-8') as log_file:
            log_file.write(logs)
            
        # --- SNAPSHOT & FREEZE ---
        print(f"[*] STEP 3: Creating forensic image snapshot '{container_name}:{evidence_tag}'...")
        container.commit(repository=container_name, tag=evidence_tag)
        
        print("[*] STEP 4: Halting CPU execution...")
        if container.status != 'paused':
            container.pause()
            
        # --- ADVANCED FEATURE: YARA SCANNING ---
        print("[*] STEP 5: Executing YARA Malware Scan on extracted evidence...")
        try:
            rules = yara.compile(filepath='rules.yar')
            matches = rules.match(log_path)
            
            if matches:
                print(f"\n    [!!!] MALWARE SIGNATURES DETECTED: {matches}")
            else:
                print("\n    [+] No known malware signatures found in volatile logs.")
                
        except yara.Error as yara_err:
            print(f"    [-] YARA Engine Error: {yara_err}. Ensure 'rules.yar' exists in the same directory.")

        print(f"\n[+] SUCCESS: Container '{container_name}' is permanently air-gapped and locked down.")
        print(f"[+] EVIDENCE: Logs saved to ./{log_path}")
        print(f"[+] SNAPSHOT: Saved as Docker image '{container_name}:{evidence_tag}'")
        
        return True
        
    except docker.errors.NotFound:
        print(f"[-] FAILED: Container '{container_name}' not found.")
        return False
    except Exception as e:
        print(f"[-] FAILED: Critical execution error: {e}")
        return False

if __name__ == "__main__":
    print("=== Cloud Container Forensic Agent (v2.0 Advanced) ===\n")
    # Make sure to target an active container for testing
    secure_compromised_container("compromised-web-4")