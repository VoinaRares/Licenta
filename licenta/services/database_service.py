import os
from dotenv import load_dotenv
from sqlmodel import create_engine, Session, text
from sqlmodel import SQLModel


load_dotenv()


engine = create_engine(os.getenv("DATABASE_URL"), echo=True)

def get_session():
    with Session(engine) as session:
        yield session
        
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def test_connection():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))