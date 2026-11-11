import io
import json
from collections.abc import Callable
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from app.config import Settings

TENANT_ID = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT_ID = "99999999-9999-9999-9999-999999999999"
API_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
DEMO_CLIENT_ID = "33333333-3333-3333-3333-333333333333"
OTHER_CLIENT_ID = "44444444-4444-4444-4444-444444444444"
ALICE_OBJECT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
ALICE_USERNAME = "alice@example.com"
BOB_OBJECT_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
BOB_USERNAME = "bob@example.com"
AUTHORITY_BASE_URL = "https://login.example"
ISSUER = f"{AUTHORITY_BASE_URL}/{TENANT_ID}/v2.0"
JWKS_URL = f"{AUTHORITY_BASE_URL}/{TENANT_ID}/discovery/v2.0/keys"
SIGNING_KEY_ID = "test-key"
INVALID_TOKEN_CHALLENGE = 'Bearer error="invalid_token"'

TokenFactory = Callable[..., str]
AuthHeadersFactory = Callable[..., dict[str, str]]


def generate_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_jwk(private_key: RSAPrivateKey, key_id: str) -> dict[str, Any]:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    return {**jwk, "kid": key_id, "use": "sig"}


def build_jwks(private_key: RSAPrivateKey, key_id: str) -> dict[str, Any]:
    return {"keys": [build_jwk(private_key, key_id)]}


def build_settings(**settings_overrides: str) -> Settings:
    values = {
        "tenant_id": TENANT_ID,
        "api_client_id": API_CLIENT_ID,
        "authority_base_url": AUTHORITY_BASE_URL,
        **settings_overrides,
    }
    return Settings(_env_file=None, **values)


class FakeJwksEndpoint:
    def __init__(self, jwks: Any) -> None:
        self.body = json.dumps(jwks).encode()
        self.error: Exception | None = None
        self.requested_urls: list[str] = []

    @property
    def request_count(self) -> int:
        return len(self.requested_urls)

    def serve_jwks(self, jwks: Any) -> None:
        self.body = json.dumps(jwks).encode()

    def open(self, request: Any) -> io.BytesIO:
        self.requested_urls.append(request.full_url)
        if self.error is not None:
            raise self.error
        return io.BytesIO(self.body)
