"""JengaSec AI API: telemetry for AI teams and the shadow-mode action gateway.
Contract: contracts/ai-api/openapi.yaml. Run: uvicorn app.main:app --port 8000"""
import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .auth import RateLimiter, load_cells, load_teams, load_tokens
from .config import Settings
from .models import Base
from .routers import platform_log, router
from .store import iso_now, json_validator, store_events, telemetry_validator


def load_assets(cells):
    """GET /assets: every application instance from scripts/cells.yaml (the canonical list on main)."""
    return [{"asset_id": f"{c['namespace']}/app", "enterprise": c["enterprise"], "application": c["application"],
             "namespace": c["namespace"], "ip": c["reserved_ip"], "service": c["service"],
             "optional": bool(c.get("optional")), "enabled": bool(c.get("enabled"))}
            for c in sorted(cells.values(), key=lambda c: (c["enterprise"], c["application"]))]


def seed_scenarios(app):
    """Sandbox only: load every committed scenarios/*/events.jsonl. Safe to repeat (event_id is unique)."""
    total = 0
    with app.state.sessions() as db:
        for path in sorted(app.state.settings.scenarios_dir.glob("s*/events.jsonl")):
            items = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            accepted, rejected, _ = store_events(db, app.state.validator, items, app.state.cells)
            total += accepted
            if rejected:
                platform_log("seed_rejected", "failure", scenario=path.parent.name, first=rejected[0]["error"])
    platform_log("sandbox_seeded", "success", events=total)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        Base.metadata.create_all(app.state.engine)
        if settings.sandbox_seed:
            seed_scenarios(app)
        platform_log("service_started", "success", ai_teams=len(app.state.tokens), sandbox=settings.sandbox_seed)
        yield
        app.state.engine.dispose()

    app = FastAPI(title="JengaSec AI API", version="1.3.0", lifespan=lifespan,
                  description="See contracts/ai-api/openapi.yaml — that file is the contract, this is the implementation.")
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    app.state.settings = settings
    app.state.engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
    app.state.sessions = sessionmaker(app.state.engine, expire_on_commit=False)
    app.state.cells = load_cells(settings)
    app.state.teams = load_teams(settings)
    app.state.tokens = load_tokens(settings, app.state.teams)
    app.state.assets = load_assets(app.state.cells)
    app.state.validator = telemetry_validator(settings)
    app.state.handoff_validator = json_validator(settings, "handoff.schema.json")
    app.state.limiter = RateLimiter(settings.rate_limit_per_minute)

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        if request.url.path != "/healthz":
            print(json.dumps({
                "ts": iso_now(), "level": "warn" if response.status_code >= 400 else "info", "service": "ai-api",
                "event": "http_request", "outcome": "success" if response.status_code < 400 else "failure",
                "method": request.method, "path": request.url.path, "status": response.status_code,
                "caller": getattr(request.state, "caller", None),
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            }, separators=(",", ":")), flush=True)
        return response

    @app.get("/healthz", include_in_schema=False)
    @app.get("/api/v1/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
