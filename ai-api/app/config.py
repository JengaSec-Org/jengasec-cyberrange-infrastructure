"""Settings, all from the environment. Defaults suit the sandbox on a laptop."""
import os
import pathlib
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent


def _default_repo() -> pathlib.Path:
    # In the repo: ai-api/app/config.py -> repo root. In the image, REPO_ROOT is set.
    return pathlib.Path(os.environ.get("REPO_ROOT", HERE.parent.parent))


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    repo: pathlib.Path = field(default_factory=_default_repo)
    database_url: str = field(default_factory=lambda: os.environ.get("DATABASE_URL", "sqlite:///./ai-api.db"))
    tokens_file: pathlib.Path = field(default_factory=lambda: pathlib.Path(os.environ.get("TOKENS_FILE", "tokens.yaml")))
    ingest_token: str = field(default_factory=lambda: os.environ.get("INGEST_TOKEN", ""))
    admin_token: str = field(default_factory=lambda: os.environ.get("ADMIN_TOKEN", ""))
    sandbox_seed: bool = field(default_factory=lambda: _flag("SANDBOX_SEED", "1"))
    action_budget: int = field(default_factory=lambda: int(os.environ.get("ACTION_BUDGET", "20")))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.environ.get("RATE_LIMIT_PER_MINUTE", "600")))
    stream_poll_seconds: float = field(default_factory=lambda: float(os.environ.get("STREAM_POLL_SECONDS", "1")))
    stream_keepalive_seconds: float = 15.0
    # The competition website's POST /api/feed (website repo: docs/CONTRACT-feed.md). Empty = do not publish.
    website_feed_url: str = field(default_factory=lambda: os.environ.get("WEBSITE_FEED_URL", ""))
    website_feed_token: str = field(default_factory=lambda: os.environ.get("WEBSITE_FEED_TOKEN", ""))
    website_competition: str = field(default_factory=lambda: os.environ.get("WEBSITE_COMPETITION", ""))
    website_ca_file: str = field(default_factory=lambda: os.environ.get("WEBSITE_CA_FILE", ""))
    # Engagement days as UTC dates, "1=2026-10-20,2=2026-10-21,3=2026-10-22"; marks are published per day.
    engagement_days: str = field(default_factory=lambda: os.environ.get("ENGAGEMENT_DAYS", ""))

    @property
    def contracts(self) -> pathlib.Path:
        return self.repo / "contracts"

    @property
    def cells_file(self) -> pathlib.Path:
        return self.repo / "scripts" / "cells.yaml"

    @property
    def ai_teams_file(self) -> pathlib.Path:
        return self.repo / "scripts" / "ai-teams.yaml"

    @property
    def scenarios_dir(self) -> pathlib.Path:
        return self.repo / "scenarios"
