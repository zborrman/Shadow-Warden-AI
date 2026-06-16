"""
warden/protocols/a2a/api.py
────────────────────────────
A2A v1.0 FastAPI router.

Routes
──────
  GET  /.well-known/agent.json          — Agent Card discovery (no auth)
  POST /a2a/tasks                       — Submit a new task
  GET  /a2a/tasks/{task_id}             — Poll task status
  POST /a2a/tasks/{task_id}/resume      — Provide additional input
  DELETE /a2a/tasks/{task_id}           — Cancel a task
  GET  /a2a/tasks                       — List recent tasks for tenant (paginated)
  GET  /a2a/task-types                  — List registered handler types
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel

from warden.auth_guard import AuthResult, require_api_key
from warden.protocols.a2a.agent_card import build_agent_card
from warden.protocols.a2a.task_lifecycle import (
    _HANDLERS,
    _mem_store,
    append_message,
    cancel_task,
    create_task,
    get_task,
    resume_task,
    run_task,
)

log = logging.getLogger("warden.protocols.a2a.api")

router     = APIRouter(tags=["A2A"])
AuthDep    = Depends(require_api_key)


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class TaskSubmit(BaseModel):
    task_type:  str
    input:      dict
    caller_did: str = ""


class TaskResume(BaseModel):
    additional_input: dict


class MessageAppend(BaseModel):
    role:    str
    content: str


# ── Agent Card ────────────────────────────────────────────────────────────────

@router.get("/.well-known/agent.json", include_in_schema=False)
async def agent_card():
    """A2A Agent Card discovery — no authentication required."""
    return build_agent_card()


# ── Task CRUD ─────────────────────────────────────────────────────────────────

@router.post("/a2a/tasks", status_code=202)
async def submit_task(
    body:       TaskSubmit,
    background: BackgroundTasks,
    auth:       AuthResult = AuthDep,
):
    """Submit a new A2A task; dispatches handler asynchronously."""
    if body.task_type not in _HANDLERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown task type '{body.task_type}'. "
                   f"Supported: {sorted(_HANDLERS.keys())}",
        )
    task = create_task(
        task_type   = body.task_type,
        input_data  = body.input,
        caller_did  = body.caller_did,
        tenant_id   = auth.tenant_id if hasattr(auth, "tenant_id") else "default",
    )
    background.add_task(_run_async_task, task["task_id"])
    return {"task_id": task["task_id"], "state": task["state"]}


async def _run_async_task(task_id: str) -> None:
    try:
        await run_task(task_id)
    except Exception as exc:
        log.exception("Background A2A task %s error: %s", task_id, exc)


@router.get("/a2a/tasks/{task_id}")
async def poll_task(task_id: str, auth: AuthResult = AuthDep):
    """Return current state of a task."""
    task = get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.post("/a2a/tasks/{task_id}/resume")
async def resume_task_endpoint(
    task_id: str,
    body:    TaskResume,
    background: BackgroundTasks,
    auth:    AuthResult = AuthDep,
):
    """Provide additional input to a task that is waiting ('input-required')."""
    task = get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["state"] != "input-required":
        raise HTTPException(
            status_code=409,
            detail=f"Task is in state '{task['state']}', not 'input-required'.",
        )
    background.add_task(_resume_async_task, task_id, body.additional_input)
    return {"task_id": task_id, "state": "submitted", "message": "Resuming task."}


async def _resume_async_task(task_id: str, additional_input: dict) -> None:
    try:
        await resume_task(task_id, additional_input)
    except Exception as exc:
        log.exception("Resume A2A task %s error: %s", task_id, exc)


@router.delete("/a2a/tasks/{task_id}", status_code=200)
async def cancel_task_endpoint(task_id: str, auth: AuthResult = AuthDep):
    """Cancel a task that has not yet completed."""
    task = cancel_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, "state": task["state"]}


@router.post("/a2a/tasks/{task_id}/messages")
async def append_message_endpoint(
    task_id: str,
    body:    MessageAppend,
    auth:    AuthResult = AuthDep,
):
    """Append a conversation message to the task history."""
    ok = append_message(task_id, body.role, body.content)
    if not ok:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"ok": True}


@router.get("/a2a/tasks")
async def list_tasks(
    limit:     int = Query(default=20, le=100),
    auth:      AuthResult = AuthDep,
):
    """Return the most recent tasks visible in this node's in-process store."""
    tenant_id = auth.tenant_id if hasattr(auth, "tenant_id") else "default"
    tasks = [
        v for v in _mem_store.values()
        if isinstance(v, dict) and v.get("tenant_id") == tenant_id
    ]
    tasks.sort(key=lambda t: t.get("created_at", 0), reverse=True)
    return tasks[:limit]


@router.get("/a2a/task-types")
async def list_task_types(auth: AuthResult = AuthDep):
    """Return registered A2A task handler types."""
    return {"task_types": sorted(_HANDLERS.keys())}
