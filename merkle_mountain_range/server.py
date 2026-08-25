"""
FastAPI REST API Server for Merkle Mountain Range (MMR) Dynamic Append-Only Cryptographic Accumulator.
"""
from typing import Dict, Any
from .models import FrontierPayload
from .agents import MMRCoordinator

coordinator = MMRCoordinator()


def create_app():
    try:
        from fastapi import FastAPI
        from pydantic import BaseModel

        app = FastAPI(
            title="Merkle Mountain Range (MMR) Dynamic Append-Only Cryptographic Accumulator",
            description="Manages binary balanced subtrees with logarithmic-sized inclusion/consistency proofs for continuous audit logging and tamper-evident blockchain state.",
            version="2.0.0-FRONTIER",
        )

        class TaskRequest(BaseModel):
            task_id: str = "TASK-2026-001"
            target_identifier: str = "TARGET-BIO-KEY"
            primary_metric: float = 28.5
            secondary_metric: float = 14.2
            status_descriptor: str = "DISCORDANT_ANOMALY"
            is_critical_flag: bool = True
            attributes: Dict[str, Any] = {}

        class ChatRequest(BaseModel):
            query: str

        @app.get("/health")
        def health():
            return {"status": "HEALTHY", "system": "merkle-mountain-range-mmr", "domain": "Post-Quantum Cryptography & Zero-Knowledge", "version": "2.0.0-FRONTIER"}

        @app.post("/api/audit")
        def api_audit(req: TaskRequest):
            payload = FrontierPayload(
                task_id=req.task_id,
                target_identifier=req.target_identifier,
                primary_metric=req.primary_metric,
                secondary_metric=req.secondary_metric,
                status_descriptor=req.status_descriptor,
                is_critical_flag=req.is_critical_flag,
                attributes=req.attributes,
            )
            return coordinator.process(payload)

        @app.post("/api/chat")
        def api_chat(req: ChatRequest):
            return {"response": coordinator.query_supervisory_chat(req.query)}

        return app
    except ImportError:
        return None
