"""
warden/api/training_records.py  (CM-38)
──────────────────────────────────────────
FastAPI router for Employee AI Training Records.

Prefix: /training
Tier:   Community Business+ (training_records_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/training", tags=["Employee AI Training"])
_Gate  = require_feature("training_records_enabled")


class ProgramCreateRequest(BaseModel):
    community_id:  str
    title:         str = Field(..., min_length=1, max_length=200)
    description:   str = ""
    required_for:  list[str] = Field(default_factory=list)
    passing_score: float = Field(0.8, ge=0.0, le=1.0)
    valid_days:    int   = Field(365, ge=1)


class CompletionCreateRequest(BaseModel):
    program_id:   str
    community_id: str
    employee_id:  str
    score:        float = Field(..., ge=0.0, le=1.0)


@router.post("/programs", summary="Create a training program", dependencies=[_Gate])
async def create_program(body: ProgramCreateRequest) -> dict:
    from warden.communities.training_records import create_program as _create
    prog = _create(
        community_id=body.community_id,
        title=body.title,
        description=body.description,
        required_for=body.required_for,
        passing_score=body.passing_score,
        valid_days=body.valid_days,
    )
    return prog.to_dict()


@router.get("/programs", summary="List training programs for a community", dependencies=[_Gate])
async def list_programs(community_id: str) -> dict:
    from warden.communities.training_records import list_programs as _list
    programs = _list(community_id)
    return {"programs": [p.to_dict() for p in programs], "count": len(programs)}


@router.get("/programs/{program_id}", summary="Get a training program", dependencies=[_Gate])
async def get_program(program_id: str) -> dict:
    from warden.communities.training_records import get_program as _get
    prog = _get(program_id)
    if not prog:
        raise HTTPException(status_code=404, detail=f"Program {program_id!r} not found")
    return prog.to_dict()


@router.post("/completions", summary="Record a training completion", dependencies=[_Gate])
async def record_completion(body: CompletionCreateRequest) -> dict:
    from warden.communities.training_records import record_completion as _record
    try:
        c = _record(
            program_id=body.program_id,
            community_id=body.community_id,
            employee_id=body.employee_id,
            score=body.score,
        )
        return c.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/employees/{employee_id}", summary="Get compliance status for an employee", dependencies=[_Gate])
async def get_employee_status(employee_id: str, community_id: str) -> dict:
    from warden.communities.training_records import get_employee_status as _status
    return _status(community_id, employee_id)


@router.get("/compliance-report", summary="Community-wide training compliance report", dependencies=[_Gate])
async def compliance_report(community_id: str) -> dict:
    from warden.communities.training_records import get_compliance_report
    return get_compliance_report(community_id)
