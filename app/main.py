import uvicorn
from fastapi import FastAPI
from app.routers import ipchecker, email, auto_containment

app = FastAPI(title="SOAR")

app.include_router(ipchecker.router)
app.include_router(email.router)
app.include_router(auto_containment.router)

@app.get("/health")
async def system_status():
    return {"status": "All SOAR modules online."}
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)