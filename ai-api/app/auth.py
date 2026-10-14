"""Bearer tokens. AI teams: one token per enabled team in scripts/ai-teams.yaml, stored only as a SHA-256
hash in TOKENS_FILE. Vector and staff: INGEST_TOKEN and ADMIN_TOKEN from the environment."""
import hashlib
import hmac
import time
from dataclasses import dataclass

import yaml
from fastapi import HTTPException, Request


@dataclass(frozen=True)
class Team:
    code: str               # AI-01 … AI-03, RI-01 … RI-06
    role: str               # ai-blue | ai-red
    paired: str | None = None
    team_id: str = ""       # the website's identifier; telemetry actor.team_id carries it

    @property
    def is_blue(self):
        return self.role == "ai-blue"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def load_cells(settings):
    """Every application instance in scripts/cells.yaml, by namespace (jengasec-ent-a-app01)."""
    data = yaml.safe_load(settings.cells_file.read_text(encoding="utf-8"))
    return {c["namespace"]: c for c in data["cells"]}


def load_teams(settings):
    data = yaml.safe_load(settings.ai_teams_file.read_text(encoding="utf-8"))
    return {t["code"]: t for t in data["teams"]}


def load_tokens(settings, teams):
    """{hash: Team} for enabled teams. A token for a disabled or unknown team is ignored."""
    if not settings.tokens_file.exists():
        return {}
    data = yaml.safe_load(settings.tokens_file.read_text(encoding="utf-8")) or {}
    out = {}
    for code, digest in (data.get("tokens") or {}).items():
        t = teams.get(code)
        if t and t.get("enabled"):
            out[digest] = Team(code, t["role"], t.get("paired"), t["team_id"])
    return out


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "missing bearer token")
    return token.strip()


class RateLimiter:
    """Fixed one-minute window per token. Enough to stop a runaway agent loop; not a security control."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.windows = {}

    def hit(self, key: str):
        window = int(time.time() // 60)
        start, count = self.windows.get(key, (window, 0))
        if start != window:
            start, count = window, 0
        count += 1
        self.windows[key] = (start, count)
        if count > self.per_minute:
            raise HTTPException(429, "over your rate limit, back off", headers={"Retry-After": "60"})


def team_auth(request: Request) -> Team:
    state = request.app.state
    team = state.tokens.get(token_hash(_bearer(request)))
    if team is None:
        raise HTTPException(401, "unknown token")
    state.limiter.hit(team.code)
    request.state.caller = team.code
    return team


def blue_auth(request: Request) -> Team:
    team = team_auth(request)
    if not team.is_blue:
        raise HTTPException(403, "AI Red teams cannot post decisions or actions; your output is traffic")
    return team


def _fixed(request: Request, expected: str, who: str):
    if not expected:
        raise HTTPException(401, f"{who} token not configured")
    if not hmac.compare_digest(_bearer(request), expected):
        raise HTTPException(401, f"unknown {who} token")
    request.state.caller = who


def ingest_auth(request: Request):
    _fixed(request, request.app.state.settings.ingest_token, "ingest")


def admin_auth(request: Request):
    _fixed(request, request.app.state.settings.admin_token, "admin")
