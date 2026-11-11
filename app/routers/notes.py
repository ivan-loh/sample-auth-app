from fastapi import APIRouter, status

from app.auth import AUTH_ERROR_RESPONSES, ReadPrincipalDep, WritePrincipalDep
from app.note_store import NoteStoreDep
from app.schemas import Note, NoteCreateRequest, NoteListResponse

router = APIRouter(prefix="/notes", tags=["notes"], responses=AUTH_ERROR_RESPONSES)


@router.get("")
def list_notes(principal: ReadPrincipalDep, note_store: NoteStoreDep) -> NoteListResponse:
    return NoteListResponse(notes=note_store.list_notes(principal.user_key))


@router.post("", status_code=status.HTTP_201_CREATED)
def create_note(
    note: NoteCreateRequest, principal: WritePrincipalDep, note_store: NoteStoreDep
) -> Note:
    return note_store.create_note(principal.user_key, note.text)
