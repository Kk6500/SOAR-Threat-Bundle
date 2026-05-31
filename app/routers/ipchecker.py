import os
import aiohttp
import asyncio
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()
router = APIRouter()

class AlertPayload(BaseModel):
        alert_id: str  = Field(..., examples=["EDR-908234-ALERT"])
        timestamp: str
        severity: str
        source_tool: str
        observable_type: str = Field(..., description ="Must be 'ip', 'domain' or 'hash'")
        observable_value: str = Field(..., description ="The indicator value")

async def abuse(session: aiohttp.ClientSession, observable_value: str) -> dict:
    url = f"https://api.abuseipdb.com/api/v2/check"
    abuseAPI = os.getenv('ABUSEIPDB_API_KEY')
    headers = {
    "accept": "application/json",
    "Key": abuseAPI
    }
    params = {
        "ipAddress": observable_value,
        "maxAgeInDays": "90"
    }
    try:
        async with session.get(url, headers=headers, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return {"malicious_score": data["data"]["abuseConfidenceScore"]}
            else:
                return {"error": f"HTTP {response.status}"}
    except Exception as e:
        return {"error": str(e)}

async def virustotal(session: aiohttp.ClientSession, observable_value: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable_value}"
    VirusTotalAPI = os.getenv('VIRUSTOTAL_API_KEY')
    headers = {
        "accept": "application/json",
        "x-apikey": VirusTotalAPI,
            }
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data
            else:
                return {"error": f"HTTP {response.status}"}
    except Exception as e:
        return {"error": str(e)}

async def synchronization(observable_value: str) -> dict:
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            abuse(session, observable_value),
            virustotal(session, observable_value)
        )
        return {
            "tested ip": observable_value,
            "abuseAPI": results[0],
            "virustotal": results[1]
        }

@router.post("/api/v1/alerts")
async def ip_checker(payload: AlertPayload):
    if not payload.alert_id.strip():
        raise HTTPException(status_code=400, detail="Invalid format")
    
    print(f" alert {payload.alert_id}")
    final_report = await synchronization(payload.observable_value)

    return {
        "status": "success",
        "data": final_report
    }