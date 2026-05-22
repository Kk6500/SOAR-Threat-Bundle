import os
import aiohttp
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from app.orchestrator import enrich_observable

# Load API Keys from .env
load_dotenv()

app = FastAPI(title="Threat Intelligence Orchestrator SOAR")

class AlertPayload(BaseModel):
        alert_id: str  = Field(..., examples=["EDR-908234-ALERT"])
        timestamp: str
        severity: str
        source_tool: str
        observable_type: str = Field(..., description ="Must be 'ip', 'domain' or 'hash'")
        observable_value: str = Field(..., description ="The indicator value")


async def fetch_alert_payload(session: aiohttp.ClientSession, observable_value: str) -> dict:
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
        return {"error": e}

async def query_virustotal(session: aiohttp.ClientSession, ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    VirusTotalAPI = os.getenv('VIRUSTOTAL_API_KEY')
    headers = {
        "accept": "application/json",
        "x-apikey": VirusTotalAPI,
            }
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return {data}
            else:
                return {"error": f"HTTP {response.status}"}
    except Exception as e:
        return {"error": str(e)}


# ==========================================
# 2. STANDALONE ASYNC CLIENTS
# ==========================================
async def fetch_warehouse_price(session: aiohttp.ClientSession, sku: str) -> dict:
    """Simulates hitting Vendor A's REST API."""
    url = f"https://mock-api.warehouse.com/v1/items/{sku}"
    
    try:
        # In the real world, you'd use: async with session.get(url) as response:
        await asyncio.sleep(1) # Simulating network latency
        return {"vendor": "Warehouse Direct", "price": 45.99, "historical_avg": 47.00}
    except Exception as e:
        return {"vendor": "Warehouse Direct", "error": str(e)}

async def fetch_retail_price(session: aiohttp.ClientSession, sku: str) -> dict:
    """Simulates hitting Vendor B's REST API."""
    url = f"https://mock-api.retail-giant.com/pricing?item={sku}"
    
    try:
        # Simulating a slower API
        await asyncio.sleep(1.5) 
        return {"vendor": "Retail Giant", "price": 49.99, "historical_avg": 52.00}
    except Exception as e:
        return {"vendor": "Retail Giant", "error": str(e)}

# ==========================================
# 3. THE ORCHESTRATOR
# ==========================================
async def aggregate_prices(sku: str) -> dict:
    """Opens a shared session and fires all requests concurrently."""
    async with aiohttp.ClientSession() as session:
        
        # asyncio.gather runs these side-by-side. 
        # Total execution time is ~1.5s (the slowest one), NOT 2.5s.
        results = await asyncio.gather(
            fetch_warehouse_price(session, sku),
            fetch_retail_price(session, sku)
        )
        
        # 'results' is a tuple containing the outputs in the exact order they were called
        return {
            "queried_sku": sku,
            "vendor_a_data": results[0],
            "vendor_b_data": results[1]
        }

# ==========================================
# 4. THE WEBHOOK LISTENER / ENDPOINT
# ==========================================
@app.post("/api/v1/pricing/compare")
async def compare_prices(payload: PriceRequest):
    # Basic validation logic
    if not payload.sku.startswith("SKU-"):
        raise HTTPException(status_code=400, detail="Invalid SKU format. Must start with SKU-")
        
    print(f"Aggregating pricing data for: {payload.sku}")
    
    # Hand off to the orchestrator
    final_report = await aggregate_prices(payload.sku)
    
    return {
        "status": "success",
        "data": final_report
    }