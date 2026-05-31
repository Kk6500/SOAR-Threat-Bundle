import os
import aiohttp
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field



class SuspiciousLogins(BaseModel):
    incident_id: str
    employee_email: str
    severity: str
    reason: str

async def suspend_user(email: str) -> dict:
    api_url = "https://api.mock-enterprise-chat.com/v1/users/deactivate"
    admin_token = os.getenv("mock_website_admin_key")

    headers ={
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    payload ={"target_user_email": email}

    async with aiohttp.ClientSession() as session:
        async with session.post(api_url, headers=headers, json=payload) as response:
            if response.status == 200:
                return await response.json()
            else:
                error_data = await response.text()
                raise Exception(f"Request Rejected {error_data}")
router = APIRouter()

@router.post("/api/v1/containment/isolate-chat-user")
async def trigger_contianment(webhook: SuspiciousLogins):
    if webhook.severity != "Critical":
        return {"status": "ignored", "message": "Severity too low for action"}
    try: 
        action_result = await suspend_user(webhook.employee_email)
        return {                
            "status": "containment_successful",
            "incident_id": webhook.incident_id,
            "target": webhook.employee_email,
            "vendor_response": action_result
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))