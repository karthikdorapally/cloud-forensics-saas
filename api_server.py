from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uvicorn
from forensic_engine import secure_compromised_container

app = FastAPI(title="Cloud Container Forensic Agent API")

# Define the expected JSON payload from the SIEM
class ThreatAlert(BaseModel):
    alert_id: str
    severity: str
    target_container: str
    description: str

@app.post("/api/v1/quarantine")
async def trigger_quarantine(alert: ThreatAlert, background_tasks: BackgroundTasks):
    """Webhook endpoint to receive SIEM alerts and trigger the forensic freeze."""
    
    if alert.severity.lower() not in ["high", "critical"]:
        return {"status": "ignored", "message": "Alert severity too low for automated quarantine."}
    
    print(f"\n[!] CRITICAL ALERT RECEIVED: {alert.description}")
    print(f"[!] Target identified: {alert.target_container}. Initiating lockdown...")
    
    # Run the freeze in the background so the API responds to the SIEM immediately
    try:
        background_tasks.add_task(secure_compromised_container, alert.target_container)
        return {
            "status": "success", 
            "message": f"Lockdown initiated for {alert.target_container}",
            "alert_reference": alert.alert_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("=== Forensic API Listener Starting on Port 8000 ===")
    uvicorn.run(app, host="0.0.0.0", port=8000)