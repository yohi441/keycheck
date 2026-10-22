from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

import os

# Configurable so a deployment (and a test) can point at a specific file. The
# default preserves the original behaviour: ./keycheck.db beside the service.
DATABASE_URL = os.getenv("KEYCHECK_DATABASE_URL", "sqlite:///./keycheck.db")

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass

def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()