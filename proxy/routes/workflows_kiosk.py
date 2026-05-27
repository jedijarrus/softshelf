"""
Kiosk-Workflow-Endpoints (v2.6) — User-Initiierte Workflows aus dem Tray.

Vier Endpoints:
- GET  /api/v1/workflows               → Liste der freigegebenen Workflows
- POST /api/v1/workflows/{id}/start    → Run starten, fire-and-forget
- GET  /api/v1/workflows/active-run    → Progress des laufenden Runs

Sicherheit: Machine-Token-Auth. Start validiert Zuweisung + kiosk_enabled +
kein paralleler Run. created_by = "kiosk:<logged_in_user>" fuer Audit-Trail.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import database
import workflow_engine
from auth import verify_machine_token

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Models ────────────────────────────────────────────────────────────────────


class WorkflowStepSummary(BaseModel):
    type: str
    label: str


class WorkflowSummary(BaseModel):
    id: int
    name: str
    description: str
    steps: list[WorkflowStepSummary]


class StartRunResponse(BaseModel):
    run_id: int


class ActiveRunResponse(BaseModel):
    id: int
    workflow_id: int
    workflow_name: str
    status: str
    current_step: int
    total_steps: int
    current_step_label: str
    current_step_type: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_steps(raw: str | None) -> list[dict]:
    if not raw:
        return []
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except Exception:
        return []


def _step_label(step: dict) -> str:
    """Menschenlesbares Label fuer einen Step (Kiosk-Anzeige).

    install → Paket-Display-Name (Fallback Paket-Name)
    script  → script_name aus Payload
    reboot  → "Neustart"
    """
    t = step.get("type", "")
    payload = step.get("payload") or {}
    if t == "install":
        return (
            payload.get("display_name")
            or payload.get("package_name")
            or "Paket installieren"
        )
    if t == "script":
        return payload.get("script_name") or payload.get("name") or "Skript ausfuehren"
    if t == "reboot":
        msg = payload.get("message")
        return msg if msg else "Neustart"
    return t or "Schritt"


async def _enrich_install_labels(steps: list[dict]) -> list[dict]:
    """Fuer install-Steps display_name aus packages-Tabelle nachschlagen
    falls nicht schon im Payload."""
    out: list[dict] = []
    for s in steps:
        if s.get("type") == "install":
            payload = s.get("payload") or {}
            if not payload.get("display_name"):
                pkg_name = payload.get("package_name")
                if pkg_name:
                    pkg = await database.get_package(pkg_name)
                    if pkg:
                        payload = dict(payload)
                        payload["display_name"] = (
                            pkg.get("display_name") or pkg.get("name") or pkg_name
                        )
                        s = {**s, "payload": payload}
        out.append(s)
    return out


def _kiosk_text(wf: dict) -> str:
    kd = (wf.get("kiosk_description") or "").strip()
    return kd or (wf.get("description") or "")


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/workflows", response_model=list[WorkflowSummary])
async def list_kiosk_workflows(token: dict = Depends(verify_machine_token)):
    """Workflows die fuer den anfragenden Agent im Kiosk verfuegbar sind.
    Schnittmenge aus agent_workflows-Zuweisung und workflows.kiosk_enabled=1."""
    agent_id = token["agent_id"]
    rows = await database.list_kiosk_workflows_for_agent(agent_id)
    result: list[WorkflowSummary] = []
    for wf in rows:
        steps = await _enrich_install_labels(_parse_steps(wf.get("steps")))
        result.append(
            WorkflowSummary(
                id=wf["id"],
                name=wf["name"],
                description=_kiosk_text(wf),
                steps=[
                    WorkflowStepSummary(type=s.get("type", ""), label=_step_label(s))
                    for s in steps
                ],
            )
        )
    return result


@router.post("/workflows/{workflow_id}/start", response_model=StartRunResponse)
async def start_kiosk_workflow(
    workflow_id: int, token: dict = Depends(verify_machine_token)
):
    """Startet einen Workflow-Run fuer den anfragenden Agent.

    Validate: workflow zugewiesen + kiosk_enabled + kein aktiver Run.
    Audit: created_by = 'kiosk:<logged_in_user>'.
    """
    agent_id = token["agent_id"]
    hostname = token.get("hostname") or ""

    visible = await database.is_workflow_kiosk_visible_for_agent(agent_id, workflow_id)
    if not visible:
        raise HTTPException(
            status_code=403,
            detail="Workflow nicht freigegeben oder nicht zugewiesen.",
        )

    agent = await database.get_agent(agent_id)
    user = (agent or {}).get("logged_in_user") or "unknown"
    created_by = f"kiosk:{user}"

    run_id = await workflow_engine.start_workflow(
        workflow_id, agent_id, hostname, created_by=created_by
    )
    logger.info(
        "kiosk: workflow_run %d gestartet von agent=%s user=%s wf=%d",
        run_id, agent_id, user, workflow_id,
    )
    return StartRunResponse(run_id=run_id)


@router.get("/workflows/active-run", response_model=ActiveRunResponse | None)
async def get_active_run(token: dict = Depends(verify_machine_token)):
    """Aktiver Workflow-Run fuer den anfragenden Agent (oder null wenn keiner)."""
    agent_id = token["agent_id"]
    run = await database.get_active_run_for_agent(agent_id)
    if not run:
        return None

    steps = _parse_steps(run.get("step_snapshot"))
    idx = run.get("current_step", 0)
    total = len(steps)
    current_step = steps[idx] if 0 <= idx < total else {}
    enriched = await _enrich_install_labels([current_step]) if current_step else []
    cur = enriched[0] if enriched else {}

    wf = await database.get_workflow(run["workflow_id"])
    wf_name = (wf or {}).get("name") or f"Workflow {run['workflow_id']}"

    return ActiveRunResponse(
        id=run["id"],
        workflow_id=run["workflow_id"],
        workflow_name=wf_name,
        status=run["status"],
        current_step=idx,
        total_steps=total,
        current_step_label=_step_label(cur) if cur else "",
        current_step_type=cur.get("type", "") if cur else "",
    )
