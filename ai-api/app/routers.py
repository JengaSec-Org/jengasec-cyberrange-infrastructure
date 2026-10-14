"""Every endpoint in contracts/ai-api/openapi.yaml, plus the staff-only kill switch and judges' export."""
import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .alerts import baseline_alerts
from .auth import Team, admin_auth, blue_auth, ingest_auth, team_auth
from .models import Action, Decision, Event, Setting
from .schemas import (ActionRecord, ActionRequest, ActionType, DecisionIn, DecisionRecord, EventPage,
                      IngestResult, KillSwitch)
from .marks import marks_for, publish
from .scoring import score_blue, score_red
from .store import (decode_cursor, encode_cursor, events_after, first_error, iso_now, parse_body, parse_ts,
                    store_events)

router = APIRouter()
KILL_SWITCH = "kill_switch"


def get_db(request: Request):
    db = request.app.state.sessions()
    try:
        yield db
    finally:
        db.close()


def kill_switch_on(db: Session) -> bool:
    row = db.get(Setting, KILL_SWITCH)
    return bool(row and row.value == "on")


def platform_log(event, outcome, **fields):
    """One JSON line on stdout, so the shared observability module records what the gateway did."""
    line = {"ts": iso_now(), "level": "info", "service": "ai-api", "event": event, "outcome": outcome, **fields}
    print(json.dumps(line, separators=(",", ":")), flush=True)


# --------------------------------------------------------------------------- telemetry

@router.get("/telemetry/events", response_model=EventPage)
def list_events(since: datetime | None = None, cursor: str | None = None,
                limit: int = Query(200, ge=1, le=1000),
                team: Team = Depends(team_auth), db: Session = Depends(get_db)):
    after = decode_cursor(cursor)
    since_utc = parse_ts(since.isoformat()) if since else None
    rows = events_after(db, team, after, limit + 1, since_utc)
    has_more = len(rows) > limit
    rows = rows[:limit]
    last = rows[-1].seq if rows else after
    return EventPage(events=[r.body for r in rows], next_cursor=encode_cursor(last), has_more=has_more)


async def stream_events(request: Request, team: Team, after: int, once: bool = False):
    settings = request.app.state.settings
    idle = 0.0
    while True:
        def fetch():
            with request.app.state.sessions() as db:
                return [(r.seq, r.body) for r in events_after(db, team, after, 500)]
        rows = await asyncio.to_thread(fetch)
        for seq, body in rows:
            after = seq
            yield f"id: {encode_cursor(seq)}\ndata: {json.dumps(body, separators=(',', ':'))}\n\n"
        if once:
            return
        if rows:
            idle = 0.0
        else:
            idle += settings.stream_poll_seconds
            if idle >= settings.stream_keepalive_seconds:
                idle = 0.0
                yield ": keep-alive\n\n"
        if await request.is_disconnected():
            return
        await asyncio.sleep(settings.stream_poll_seconds)


@router.get("/telemetry/stream")
def stream(request: Request, cursor: str | None = None, team: Team = Depends(team_auth),
           db: Session = Depends(get_db)):
    # Default is "from now". The cursor is a global position, so it reveals nothing about other teams.
    after = decode_cursor(cursor) if cursor else (db.scalar(select(func.max(Event.seq))) or 0)
    return StreamingResponse(stream_events(request, team, after), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------- assets and alerts

@router.get("/assets")
def assets(request: Request, team: Team = Depends(team_auth)):
    """All 18 applications in both enterprises: AI Blue watches them all, AI Red may target them all."""
    return request.app.state.assets


@router.get("/alerts")
def alerts(team: Team = Depends(team_auth), db: Session = Depends(get_db)):
    rows = list(db.scalars(select(Event).order_by(Event.seq.desc()).limit(50000)))
    rows.reverse()
    found = baseline_alerts(rows)
    if team.is_blue:
        return found
    # AI Red: only alerts its own traffic triggered, with evidence trimmed to its own events.
    own = {r.event_id for r in rows if r.team_id == team.team_id}
    out = []
    for a in found:
        mine = [e for e in a["evidence"] if e in own]
        if mine:
            out.append({**a, "evidence": mine})
    return out


# --------------------------------------------------------------------------- actions (shadow mode, AI Blue only)

def _record(a: Action, remaining=None) -> dict:
    return ActionRecord(action_id=a.action_id, type=a.type, status=a.status, effective=a.effective,
                        budget_remaining=remaining).model_dump(exclude_none=True)


@router.post("/actions/{type}", status_code=202, response_model=ActionRecord, response_model_exclude_none=True)
def request_action(type: ActionType, req: ActionRequest, request: Request,
                   team: Team = Depends(blue_auth), db: Session = Depends(get_db)):
    target = request.app.state.cells.get(req.target.namespace)
    if target is None or not target.get("enabled"):
        raise HTTPException(403, f"{req.target.namespace} is not an enabled application in the range")

    today = datetime.now(timezone.utc).replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
    used = db.scalar(select(func.count(Action.id)).where(
        Action.team == team.code, Action.status != "halted", Action.created_at >= today)) or 0
    budget = request.app.state.settings.action_budget
    halted = kill_switch_on(db)
    if not halted and used >= budget:
        raise HTTPException(403, f"over budget: {budget} actions per engagement day")

    n = (db.scalar(select(func.max(Action.id))) or 0) + 1
    action = Action(action_id=f"act-{n:06d}", team=team.code, namespace=req.target.namespace, type=type,
                    target=req.target.model_dump(exclude_none=True), parameters=req.parameters,
                    justification=req.justification, incident_id=req.incident_id, evidence=req.evidence,
                    status="halted" if halted else "recorded", effective=(type == "alert" and not halted))
    db.add(action)
    db.commit()
    platform_log("shadow_action", "denied" if halted else "success", team=team.code, action_id=action.action_id,
                 type=type, target=action.target, effective=action.effective)
    if halted:
        return JSONResponse(status_code=423, content=_record(action))
    return _record(action, remaining=budget - used - 1)


@router.post("/actions/{id}/revert", status_code=202, response_model=ActionRecord, response_model_exclude_none=True)
def revert_action(id: str, team: Team = Depends(blue_auth), db: Session = Depends(get_db)):
    action = db.scalar(select(Action).where(Action.action_id == id))
    if action is None:
        raise HTTPException(404, "no such action")
    if action.team != team.code:
        raise HTTPException(403, "not your action")
    if action.status == "recorded":
        action.status, action.effective = "reverted", False
        action.reverted_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
        platform_log("shadow_action_reverted", "success", team=team.code, action_id=action.action_id)
    return _record(action)


# --------------------------------------------------------------------------- decisions (AI Blue only)

@router.post("/decisions", status_code=201, response_model=DecisionRecord)
def post_decision(body: DecisionIn, request: Request, team: Team = Depends(blue_auth), db: Session = Depends(get_db)):
    found = set(db.scalars(select(Event.event_id).where(Event.event_id.in_(body.evidence))))
    missing = [e for e in body.evidence if e not in found]
    if missing:
        raise HTTPException(422, f"evidence not found: {', '.join(missing[:5])}")
    if body.handoff is not None:
        error = first_error(request.app.state.handoff_validator, body.handoff)
        if error:
            raise HTTPException(422, f"handoff: {error}")
    n = (db.scalar(select(func.max(Decision.id))) or 0) + 1
    decision = Decision(decision_id=f"dec-{n:06d}", team=team.code, body=body.model_dump(exclude_none=True))
    db.add(decision)
    db.commit()
    return DecisionRecord(decision_id=decision.decision_id, ts=decision.created_at.isoformat(timespec="milliseconds") + "Z")


# --------------------------------------------------------------------------- ingest (Vector only)

@router.post("/ingest", status_code=202, response_model=IngestResult, dependencies=[Depends(ingest_auth)])
async def ingest(request: Request):
    """A JSON array or NDJSON of v2 telemetry events (Vector's http sink sends either)."""
    raw = await request.body()
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(413, "batch too large: at most 20 MB")
    try:
        items = parse_body(raw)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "body is neither a JSON array nor NDJSON") from None
    if not isinstance(items, list) or len(items) > 5000:
        raise HTTPException(422, "send at most 5000 events per batch")
    state = request.app.state

    def work():
        with state.sessions() as db:
            return store_events(db, state.validator, items, state.cells)
    accepted, rejected, mismatches = await asyncio.to_thread(work)
    if rejected:
        platform_log("ingest_rejected", "failure", count=len(rejected), first=rejected[0]["error"])
    if mismatches:
        platform_log("ingest_integrity_mismatch", "failure", count=mismatches)
    return IngestResult(accepted=accepted, rejected=rejected)


# --------------------------------------------------------------------------- staff and judges (not in the AI team contract)

@router.get("/admin/kill-switch", response_model=KillSwitch, dependencies=[Depends(admin_auth)], include_in_schema=False)
def get_kill_switch(db: Session = Depends(get_db)):
    return KillSwitch(on=kill_switch_on(db))


@router.post("/admin/kill-switch", response_model=KillSwitch, dependencies=[Depends(admin_auth)], include_in_schema=False)
def set_kill_switch(body: KillSwitch, db: Session = Depends(get_db)):
    row = db.get(Setting, KILL_SWITCH) or Setting(key=KILL_SWITCH, value="off")
    row.value = "on" if body.on else "off"
    db.merge(row)
    db.commit()
    platform_log("kill_switch", "success", on=body.on)
    return body


@router.get("/admin/teams", dependencies=[Depends(admin_auth)], include_in_schema=False)
def teams_overview(request: Request, db: Session = Depends(get_db)):
    state = request.app.state
    issued = {t.code for t in state.tokens.values()}
    out = []
    for code, t in state.teams.items():
        row = {"code": code, "team_id": t["team_id"], "role": t["role"], "enabled": t.get("enabled", False),
               "token_issued": code in issued}
        if t["role"] == "ai-blue":
            row["decisions"] = db.scalar(select(func.count(Decision.id)).where(Decision.team == code)) or 0
            row["actions"] = db.scalar(select(func.count(Action.id)).where(Action.team == code)) or 0
        else:
            row["paired"] = t.get("paired")
            row["own_events"] = db.scalar(select(func.count(Event.seq)).where(Event.team_id == t["team_id"])) or 0
        out.append(row)
    return out


@router.get("/admin/export/{code}", dependencies=[Depends(admin_auth)], include_in_schema=False)
def export_team(code: str, request: Request, db: Session = Depends(get_db)):
    """One file per AI team for the Scoring lead (AIC-20): everything it did, plus ground-truth numbers."""
    state = request.app.state
    t = state.teams.get(code)
    if t is None:
        raise HTTPException(404, "no such team")
    out = {"team": code, "team_id": t["team_id"], "role": t["role"], "exported_at": iso_now()}
    if t["role"] == "ai-blue":
        out["decisions"] = [{"decision_id": d.decision_id, "ts": d.created_at.isoformat() + "Z", **d.body}
                            for d in db.scalars(select(Decision).where(Decision.team == code).order_by(Decision.id))]
        out["actions"] = [{"action_id": a.action_id, "ts": a.created_at.isoformat() + "Z", "type": a.type,
                           "status": a.status, "effective": a.effective, "target": a.target,
                           "justification": a.justification, "incident_id": a.incident_id, "evidence": a.evidence}
                          for a in db.scalars(select(Action).where(Action.team == code).order_by(Action.id))]
        out["ground_truth"] = score_blue(db, code)
    else:
        enabled = sum(1 for c in state.cells.values() if c.get("enabled")) or 18
        out["ground_truth"] = score_red(db, Team(code, "ai-red", t.get("paired"), t["team_id"]), t.get("paired"), enabled)
    return out


@router.get("/admin/marks", dependencies=[Depends(admin_auth)], include_in_schema=False)
def preview_marks(request: Request, day: int | None = None, db: Session = Depends(get_db)):
    """The marks that publishing would send to the website, without sending them."""
    try:
        return marks_for(db, request.app.state, day)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@router.post("/admin/publish-marks", dependencies=[Depends(admin_auth)], include_in_schema=False)
def publish_marks(request: Request, day: int | None = None, db: Session = Depends(get_db)):
    """Push proposed AI marks to the website's POST /api/feed (idempotent per criterion and day)."""
    settings = request.app.state.settings
    if not (settings.website_feed_url and settings.website_feed_token):
        raise HTTPException(409, "WEBSITE_FEED_URL and WEBSITE_FEED_TOKEN are not set on this VM")
    try:
        rows = marks_for(db, request.app.state, day)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    status, answer = publish(settings, rows)
    platform_log("marks_published", "success" if status < 300 else "failure", day=day, rows=len(rows),
                 website_status=status, rejected=len((answer or {}).get("rejected") or []))
    return {"sent": len(rows), "website_status": status, "website_answer": answer}
