"""
Security Scanner Environment — FastAPI Application
Exposes the OpenEnv-compatible REST API on port 7860.
"""

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from environment.env import SecurityScannerEnv
from environment.models import Action, ActionType, TaskInfo


app = FastAPI(
    title="Security Vulnerability Scanner Environment",
    description="An OpenEnv RL environment for training security auditing agents.",
    version="1.0.0",
)

# CORS — allow all origins (judges call from different machines)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single global environment instance (one episode at a time)
env = SecurityScannerEnv()


# ─── Request models ───────────────────────────────────────────

class ResetRequest(BaseModel):
    # Default lets automated pings (e.g. validate-submission.sh with body {}) succeed.
    task_id: int = 1


# ─── Helper functions ─────────────────────────────────────────

def get_all_tasks() -> list[TaskInfo]:
    """Load task info for all 3 tasks."""
    from environment.tasks import Task1SingleFile, Task2MultiFile, Task3RealWorld

    return [
        Task1SingleFile().get_task_info(),
        Task2MultiFile().get_task_info(),
        Task3RealWorld().get_task_info(),
    ]


def compact_task_payload(tasks: list[TaskInfo]) -> list[dict]:
    """Return compact task metadata for validator-friendly endpoints."""
    return [
        {"id": t.task_id, "name": t.name, "difficulty": t.difficulty}
        for t in tasks
    ]


# ─── Exception handlers ──────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc), "type": "validation_error"},
    )


@app.exception_handler(RuntimeError)
async def runtime_error_handler(request, exc):
    return JSONResponse(
        status_code=409,
        content={"detail": str(exc), "type": "state_error"},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc), "type": "invalid_input"},
    )


# ─── Endpoints ────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "1.0.0"}


@app.get("/tasks")
async def list_tasks():
    """List all available tasks with metadata."""
    tasks = get_all_tasks()
    return {"tasks": [t.model_dump() for t in tasks]}


@app.post("/reset")
async def reset(request: ResetRequest):
    """Start a new episode for the given task."""
    if request.task_id not in (1, 2, 3):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid task_id: {request.task_id}. Must be 1, 2, or 3.",
        )

    observation = env.reset(request.task_id)
    return observation.model_dump()


@app.post("/step")
async def step(action: Action):
    """Submit an agent action and receive the step result."""
    try:
        result = env.step(action)
        return result.model_dump()
    except HTTPException:
        raise
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid action: {e}")


@app.get("/state")
async def get_state():
    """Get the current episode state."""
    try:
        return env.state()
    except HTTPException:
        raise


@app.get("/validate")
async def validate():
    """OpenEnv validation endpoint — returns spec compliance info."""
    tasks = get_all_tasks()
    return {
        "openenv_compliant": True,
        "spec_version": "1.0",
        "environment_name": "security-vulnerability-scanner",
        "endpoints": ["/reset", "/step", "/state", "/tasks", "/health", "/validate"],
        "observation_fields": [
            "files",
            "current_findings",
            "step_number",
            "task_id",
            "feedback",
            "remaining_steps",
            "active_insights",
            "suspicious_files",
        ],
        "action_types": [
            "report_vulnerability",
            "request_file",
            "mark_complete",
            "add_note",
        ],
        "tasks": compact_task_payload(tasks),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
