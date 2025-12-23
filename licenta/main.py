from fastapi import FastAPI
from licenta.api import encrypt
from licenta.services.database_service import test_connection
from contextlib import asynccontextmanager



@asynccontextmanager
async def lifespan(app: FastAPI):
    test_connection()
    yield
    
app = FastAPI(lifespan=lifespan)

app.include_router(encrypt.router, prefix="/encrypt", tags=["encrypt"])