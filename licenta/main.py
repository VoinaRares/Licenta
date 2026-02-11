from fastapi import FastAPI
from licenta.api import encrypt
from licenta.api import auth
from licenta.services.database_service import test_connection, create_db_and_tables
from contextlib import asynccontextmanager



@asynccontextmanager
async def lifespan(app: FastAPI):
    test_connection()
    create_db_and_tables()
    yield
    
app = FastAPI(lifespan=lifespan)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(encrypt.router, prefix="/encrypt", tags=["encrypt"])