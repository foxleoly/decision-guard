import os
import uvicorn
from fastapi import FastAPI, Request
from service import Jev2bService

# Configuration from environment or defaults
MODEL_PATH = os.getenv("JEV2B_MODEL_PATH", "/Users/foxleoly/.lmstudio/models/chaoliangUNSW/Jev-Style-Qwen3.5-2B-Decision-MLX-bf16")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8093"))

app = FastAPI()
service = Jev2bService(MODEL_PATH)

@app.post("/v1/systemone")
async def systemone_endpoint(request: Request):
    """
    Implements the systemone contract endpoint.
    """
    try:
        request_data = await request.json()
        response = service.handle_request(request_data)
        return response
    except Exception as e:
        return {"type": "refusal", "error": str(e)}

if __name__ == "__main__":
    print(f"Starting Jev2b service on {HOST}:{PORT}...")
    uvicorn.run(app, host=HOST, port=PORT)
