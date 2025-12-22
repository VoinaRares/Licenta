from fastapi import FastAPI, Depends
from licenta.api import encrypt
from dotenv import load_dotenv
import os
from sqlmodel import create_engine, Session
from typing import Annotated

load_dotenv()

connect_args = {"check_same_thread": False}

engine = create_engine(os.getenv("DATABASE_URL"), connect_args=connect_args)

def get_session():
    with Session(engine) as session:
        yield session
        
SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}

app.include_router(encrypt.router, prefix="/encrypt", tags=["encrypt"])