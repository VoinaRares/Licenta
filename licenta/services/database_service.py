import os
from dotenv import load_dotenv
from sqlmodel import create_engine, Session, text
from sqlmodel import SQLModel


load_dotenv()

_url = os.getenv("DATABASE_URL")
if not _url:
    raise SystemExit("DATABASE_URL is not set. Add it to your .env file or environment.")

engine = create_engine(_url)

def get_session():
    with Session(engine) as session:
        yield session
        
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def test_connection():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))