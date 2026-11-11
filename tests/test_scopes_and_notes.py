from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.helpers import BOB_OBJECT_ID, AuthHeadersFactory

READ_CHALLENGE = 'Bearer error="insufficient_scope", scope="Notes.Read"'
WRITE_CHALLENGE = 'Bearer error="insufficient_scope", scope="Notes.ReadWrite"'


def test_read_scope_can_read(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory
) -> None:
    headers = build_auth_headers(scp="Notes.Read")

    assert api_test_client.get("/whoami", headers=headers).status_code == 200
    assert api_test_client.get("/notes", headers=headers).status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"text": "x"}, id="valid-note"),
        pytest.param({}, id="invalid-note"),
    ],
)
def test_read_scope_cannot_write(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory, payload: dict[str, str]
) -> None:
    response = api_test_client.post(
        "/notes", headers=build_auth_headers(scp="Notes.Read"), json=payload
    )

    assert response.status_code == 403
    assert response.headers["WWW-Authenticate"] == WRITE_CHALLENGE


def test_write_scope_can_read_and_write(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory
) -> None:
    headers = build_auth_headers(scp="Notes.ReadWrite")

    assert api_test_client.post("/notes", headers=headers, json={"text": "x"}).status_code == 201
    assert api_test_client.get("/notes", headers=headers).status_code == 200
    assert api_test_client.get("/whoami", headers=headers).json()["scopes"] == ["Notes.ReadWrite"]


@pytest.mark.parametrize(
    "token_overrides",
    [
        pytest.param(
            {"omitted_claims": ("scp",), "roles": ["Notes.ReadWrite"]}, id="app-only-token"
        ),
        pytest.param({"scp": ""}, id="empty-scope-claim"),
        pytest.param({"scp": ["Notes.Read"]}, id="scope-claim-not-a-string"),
        pytest.param({"scp": "Other.Scope"}, id="scope-of-no-endpoint"),
        pytest.param({"scp": "Notes.ReadWriteAll Notes Notes.Rea"}, id="similar-scope-names"),
        pytest.param({"scp": "notes.read"}, id="different-letter-case"),
        pytest.param({"scp": "Other.Scope\tNotes.Read"}, id="scope-after-a-tab"),
    ],
)
def test_token_without_the_required_scope_is_403_insufficient_scope(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    token_overrides: dict[str, Any],
) -> None:
    response = api_test_client.get("/notes", headers=build_auth_headers(**token_overrides))

    assert response.status_code == 403
    assert response.headers["WWW-Authenticate"] == READ_CHALLENGE


def test_created_note_is_returned_and_listed(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory
) -> None:
    headers = build_auth_headers()

    created = api_test_client.post("/notes", headers=headers, json={"text": "First note"})
    listed = api_test_client.get("/notes", headers=headers)

    assert created.status_code == 201
    assert created.json()["text"] == "First note"
    assert set(created.json()) == {"id", "text", "created_at"}
    assert listed.json() == {"notes": [created.json()]}


def test_other_user_cannot_see_the_notes_of_a_user(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory
) -> None:
    headers_of_alice = build_auth_headers()
    headers_of_bob = build_auth_headers(oid=BOB_OBJECT_ID)

    created = api_test_client.post("/notes", headers=headers_of_alice, json={"text": "Note"})
    notes_of_alice = api_test_client.get("/notes", headers=headers_of_alice).json()["notes"]
    notes_of_bob = api_test_client.get("/notes", headers=headers_of_bob).json()["notes"]

    assert created.status_code == 201
    assert [note["text"] for note in notes_of_alice] == ["Note"]
    assert notes_of_bob == []


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"text": ""}, id="empty-text"),
        pytest.param({"text": "x" * 2001}, id="text-too-long"),
        pytest.param({}, id="no-text"),
    ],
)
def test_invalid_note_is_422(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory, payload: dict[str, str]
) -> None:
    response = api_test_client.post("/notes", headers=build_auth_headers(), json=payload)

    assert response.status_code == 422


def test_invalid_note_without_a_token_is_401(api_test_client: TestClient) -> None:
    response = api_test_client.post("/notes", json={})

    assert response.status_code == 401
