from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.routers import health, notes, whoami
from app.signing_keys import build_jwk_client


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    build_jwk_client(get_settings().jwks_url)
    yield


app = FastAPI(title="Sample API protected by Entra ID", lifespan=lifespan)

app.include_router(health.router)
app.include_router(whoami.router)
app.include_router(notes.router)
