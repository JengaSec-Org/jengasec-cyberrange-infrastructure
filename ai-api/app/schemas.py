"""Request and response bodies, mirroring the components in contracts/ai-api/openapi.yaml."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NAMESPACE_PATTERN = r"^jengasec-ent-(a|b)-app0[1-9]$"
ActionType = Literal["alert", "block-ip", "revoke-session", "disable-account", "rate-limit",
                     "isolate-workload", "snapshot-evidence"]
Severity = Literal["low", "medium", "high", "critical"]


class EventPage(BaseModel):
    events: list[dict]
    next_cursor: str
    has_more: bool


class IngestResult(BaseModel):
    accepted: int
    rejected: list[dict]


class ActionTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str = Field(pattern=NAMESPACE_PATTERN)
    ip: str | None = None
    user_id: str | None = None
    session: str | None = None


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: ActionTarget
    parameters: dict = {}
    justification: str = Field(min_length=1)
    incident_id: str | None = None
    evidence: list[str] = []


class ActionRecord(BaseModel):
    action_id: str
    type: str
    status: Literal["recorded", "halted", "reverted"]
    effective: bool
    budget_remaining: int | None = None


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    attack_mapping: list[str] = []
    confidence: float = Field(ge=0, le=1)
    severity: Severity | None = None
    evidence: list[str] = Field(min_length=1)
    actions: list[str] = []
    handoff: dict | None = None


class DecisionRecord(BaseModel):
    decision_id: str
    ts: str


class KillSwitch(BaseModel):
    on: bool
