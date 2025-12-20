from fastapi import FastAPI
from licenta.api import encrypt_vibe
from cryptography.fernet import Fernet

print(Fernet.generate_key())


app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}

app.include_router(encrypt_vibe.router, prefix="/encrypt", tags=["encrypt"])