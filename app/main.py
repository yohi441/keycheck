from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .database import Base, engine
from . import models  # noqa: F401 (registers the table)
from .routers import auth, licenses

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

Base.metadata.create_all(bind=engine)

app = FastAPI(title="KeyCheck API", description="API for checking keys", version="1.0.0")
app.include_router(licenses.router)
app.include_router(auth.router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/")
def root():
    return {"message": "Welcome to the KeyCheck API!"}

