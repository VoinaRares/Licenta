from fastapi import FastAPI
from pydantic import BaseModel
import json
import os

app = FastAPI()

class StoreShareInput(BaseModel):
    object_id: int
    share_id: int
    x: int
    y: str

STORAGE_DIR = "shares"
os.makedirs(STORAGE_DIR, exist_ok=True)

@app.post("/store_share")
def store_share(inp: StoreShareInput):
    path = os.path.join(STORAGE_DIR, f"share_{inp.object_id}.json")

    with open(path, "w") as f:
        json.dump(inp.model_dump(), f)

    return {"status": "stored"}


@app.get("/retrieve_share")
def retrieve_share(object_id: int):
    path = os.path.join(STORAGE_DIR, f"share_{object_id}.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)

    for fname in os.listdir(STORAGE_DIR):
        if not fname.endswith('.json'):
            continue
        try:
            with open(os.path.join(STORAGE_DIR, fname), 'r') as f:
                data = json.load(f)
            if str(data.get('object_id', '')) == str(object_id):
                return data
        except Exception:
            continue

    return {"error": "Share not found"}


@app.get("/health")
def health():
    return {"status":"ok"}