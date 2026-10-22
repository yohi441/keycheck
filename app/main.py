from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .database import Base, engine
from . import models  # noqa: F401 (registers the table)
from .migrations import run_migrations, schema_problems
from .routers import auth, licenses

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# create_all builds any missing table. run_migrations then brings an *existing*
# table up to date, because create_all will not add columns (see migrations.py).
Base.metadata.create_all(bind=engine)
run_migrations(engine)

import os

docs_enabled = os.getenv("KEYCHECK_ENV", "development") != "production"

app = FastAPI(
    title="KeyCheck API",
    description="API for checking keys",
    version="1.0.0",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)
app.include_router(licenses.router)
app.include_router(auth.router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/health")
def health():
    """Liveness plus a schema self-check.

    The schema check matters because a deployment pointed at a database that
    was not migrated would otherwise look healthy right up until someone tried
    to issue a signed key.
    """
    problems = schema_problems(engine)
    return {"status": "ok" if not problems else "degraded", "problems": problems}


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/signed-keys", include_in_schema=False)
def signed_keys_page():
    """The Clinic Manager key page.

    Deliberately a separate page from the dashboard: issuing a signed,
    machine-bound product key is a different job from the original random-key
    workflow, and mixing them on one screen made it easy to click the wrong
    button. This page only ever touches signed keys.
    """
    return FileResponse(STATIC_DIR / "signed_keys.html")


@app.get("/")
def root():
    return {"message": "Welcome to the KeyCheck API!"}

