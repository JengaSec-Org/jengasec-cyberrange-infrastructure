"""Database tables. SQLite for the sandbox, PostgreSQL 16 for the competition (DATABASE_URL)."""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Event(Base):
    """One normalized telemetry event (contract v2). `seq` is the ingestion order and drives the cursor."""
    __tablename__ = "events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(80), unique=True)
    enterprise: Mapped[str] = mapped_column(String(8), index=True)
    application: Mapped[str] = mapped_column(String(8))
    namespace: Mapped[str] = mapped_column(String(40), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)       # naive UTC
    actor_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    team_label: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)  # actor.team_label (OBS)
    team_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)     # actor.team_id (OBS)
    body: Mapped[dict] = mapped_column(JSON)


class Action(Base):
    """Every action an AI Blue team asked for, effective or not. Scoring reads this table (AIC-20)."""
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String(32), unique=True)
    team: Mapped[str] = mapped_column(String(16), index=True)        # AI team code, e.g. AI-01
    namespace: Mapped[str] = mapped_column(String(40))
    type: Mapped[str] = mapped_column(String(32))
    target: Mapped[dict] = mapped_column(JSON)
    parameters: Mapped[dict] = mapped_column(JSON)
    justification: Mapped[str] = mapped_column(Text)
    incident_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))                  # recorded | halted | reverted
    effective: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reverted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Decision(Base):
    """A decision-log entry, kept verbatim. This is what judges score."""
    __tablename__ = "decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(32), unique=True)
    team: Mapped[str] = mapped_column(String(16), index=True)
    body: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Setting(Base):
    """Small key/value switches, e.g. the gateway kill switch."""
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))
