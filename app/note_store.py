import threading
from datetime import UTC, datetime
from typing import Annotated
from uuid import uuid4

from fastapi import Depends

from app.auth import UserKey
from app.schemas import Note


class NoteStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._notes_by_user: dict[UserKey, list[Note]] = {}

    def list_notes(self, user_key: UserKey) -> list[Note]:
        with self._lock:
            return list(self._notes_by_user.get(user_key, []))

    def create_note(self, user_key: UserKey, text: str) -> Note:
        note = Note(id=uuid4(), text=text, created_at=datetime.now(UTC))
        with self._lock:
            self._notes_by_user.setdefault(user_key, []).append(note)
        return note


note_store = NoteStore()


def get_note_store() -> NoteStore:
    return note_store


NoteStoreDep = Annotated[NoteStore, Depends(get_note_store)]
