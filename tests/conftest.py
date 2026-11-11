import io
import time
import urllib.request
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.testclient import TestClient

from app.auth import SIGNING_ALGORITHM
from app.config import get_settings
from app.main import app
from app.note_store import NoteStore, get_note_store
from app.signing_keys import build_jwk_client
from tests.helpers import (
    ALICE_OBJECT_ID,
    ALICE_USERNAME,
    API_CLIENT_ID,
    DEMO_CLIENT_ID,
    ISSUER,
    SIGNING_KEY_ID,
    TENANT_ID,
    AuthHeadersFactory,
    FakeJwksEndpoint,
    TokenFactory,
    build_jwks,
    build_settings,
    generate_private_key,
)


@pytest.fixture(scope="session")
def private_key() -> RSAPrivateKey:
    return generate_private_key()


@pytest.fixture(scope="session")
def other_private_key() -> RSAPrivateKey:
    return generate_private_key()


@pytest.fixture
def jwks_endpoint(
    monkeypatch: pytest.MonkeyPatch, private_key: RSAPrivateKey
) -> Iterator[FakeJwksEndpoint]:
    endpoint = FakeJwksEndpoint(build_jwks(private_key, SIGNING_KEY_ID))

    def open_url(opener: Any, request: Any, data: Any = None, timeout: Any = None) -> io.BytesIO:
        return endpoint.open(request)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", open_url)
    build_jwk_client.cache_clear()
    yield endpoint
    build_jwk_client.cache_clear()


@pytest.fixture
def api_test_client(jwks_endpoint: FakeJwksEndpoint) -> Iterator[TestClient]:
    note_store = NoteStore()
    app.dependency_overrides[get_settings] = lambda: build_settings()
    app.dependency_overrides[get_note_store] = lambda: note_store
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def build_token(private_key: RSAPrivateKey) -> TokenFactory:
    def build(
        signing_private_key: RSAPrivateKey | str | None = None,
        key_id: str = SIGNING_KEY_ID,
        algorithm: str = SIGNING_ALGORITHM,
        omitted_claims: tuple[str, ...] = (),
        **claim_overrides: Any,
    ) -> str:
        issued_at = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": API_CLIENT_ID,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + 600,
            "tid": TENANT_ID,
            "oid": ALICE_OBJECT_ID,
            "name": "Alice",
            "preferred_username": ALICE_USERNAME,
            "scp": "Notes.Read Notes.ReadWrite",
            "azp": DEMO_CLIENT_ID,
            **claim_overrides,
        }
        for claim_name in omitted_claims:
            del claims[claim_name]
        return jwt.encode(
            claims,
            signing_private_key or private_key,
            algorithm=algorithm,
            headers={"kid": key_id},
        )

    return build


@pytest.fixture
def build_auth_headers(build_token: TokenFactory) -> AuthHeadersFactory:
    def build(**token_overrides: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {build_token(**token_overrides)}"}

    return build
