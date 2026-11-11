from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str


class WhoAmIResponse(BaseModel):
    tenant_id: str
    object_id: str
    name: str | None
    username: str | None
    scopes: list[str]
    client_id: str | None


class NoteCreateRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class Note(BaseModel):
    id: UUID
    text: str
    created_at: datetime


class NoteListResponse(BaseModel):
    notes: list[Note]
