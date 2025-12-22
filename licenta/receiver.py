from fastapi import FastAPI
from pydantic import BaseModel
import json
import os

app = FastAPI()

class StoreShareInput(BaseModel):
    share_id: int
    x: int
    y: str

STORAGE_DIR = "shares"
os.makedirs(STORAGE_DIR, exist_ok=True)

@app.post("/store_share")
def store_share(inp: StoreShareInput):
    path = os.path.join(STORAGE_DIR, f"share_{inp.share_id}.json")

    with open(path, "w") as f:
        json.dump(inp.model_dump(), f)

    return {"status": "stored"}
