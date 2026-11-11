from fastapi import APIRouter

from app.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz")
def read_health() -> HealthResponse:
    return HealthResponse(status="ok")
