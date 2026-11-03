import pytest
from fastapi.testclient import TestClient
import os

# Import your FastAPI app
from api_server import app

# Create a test client that bypasses the network and tests the code directly
client = TestClient(app)

def test_api_rejects_low_severity():
    """Ensure the API ignores low-level threats to prevent false-positive lockouts."""
    payload = {
        "alert_id": "TEST-001",
        "severity": "low",
        "target_container": "production-db",
        "description": "Minor anomaly detected"
    }
    response = client.post("/api/v1/quarantine", json=payload)
    
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"

def test_api_accepts_critical_severity():
    """Ensure the API correctly processes critical alerts."""
    payload = {
        "alert_id": "TEST-002",
        "severity": "critical",
        "target_container": "compromised-web-4",
        "description": "Reverse shell detected"
    }
    response = client.post("/api/v1/quarantine", json=payload)
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_invalid_json_payload():
    """Ensure the API does not crash when a SIEM sends malformed or missing data."""
    payload = {
        "wrong_field": "TEST-003",
        "missing_severity": True
    }
    response = client.post("/api/v1/quarantine", json=payload)
    
    # FastAPI should automatically catch this and return a 422 Unprocessable Entity, not a 500 Crash
    assert response.status_code == 422 

def test_yara_rules_exist():
    """Ensure the YARA malware signatures are physically present on the disk."""
    assert os.path.exists("rules.yar") == True