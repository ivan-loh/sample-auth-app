import base64
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from tests.helpers import (
    ALICE_OBJECT_ID,
    ALICE_USERNAME,
    API_CLIENT_ID,
    DEMO_CLIENT_ID,
    INVALID_TOKEN_CHALLENGE,
    ISSUER,
    JWKS_URL,
    OTHER_CLIENT_ID,
    OTHER_TENANT_ID,
    SIGNING_KEY_ID,
    TENANT_ID,
    AuthHeadersFactory,
    FakeJwksEndpoint,
    build_settings,
)

BARE_CHALLENGE = "Bearer"


def encode_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def encode_json_segment(value: dict[str, Any]) -> str:
    return encode_segment(json.dumps(value).encode())


def test_whoami_returns_the_identity_in_the_token(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
) -> None:
    response = api_test_client.get("/whoami", headers=build_auth_headers())

    assert response.status_code == 200
    assert response.json() == {
        "tenant_id": TENANT_ID,
        "object_id": ALICE_OBJECT_ID,
        "name": "Alice",
        "username": ALICE_USERNAME,
        "scopes": ["Notes.Read", "Notes.ReadWrite"],
        "client_id": DEMO_CLIENT_ID,
    }
    assert jwks_endpoint.requested_urls == [JWKS_URL]


@pytest.mark.parametrize(
    "token_overrides",
    [
        pytest.param({"omitted_claims": ("name", "preferred_username")}, id="no-name-claims"),
        pytest.param({"name": 5, "preferred_username": ["alice"]}, id="name-claims-not-strings"),
    ],
)
def test_whoami_returns_null_for_an_unusable_name_and_username(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    token_overrides: dict[str, Any],
) -> None:
    response = api_test_client.get("/whoami", headers=build_auth_headers(**token_overrides))

    assert response.status_code == 200
    assert response.json()["name"] is None
    assert response.json()["username"] is None


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no-header"),
        pytest.param({"Authorization": "Basic dXNlcjpwYXNz"}, id="other-scheme"),
        pytest.param({"Authorization": "Bearer"}, id="no-token"),
    ],
)
def test_request_without_a_bearer_token_is_401_with_a_bare_challenge(
    api_test_client: TestClient, headers: dict[str, str]
) -> None:
    response = api_test_client.get("/whoami", headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == BARE_CHALLENGE


def test_malformed_token_is_401_invalid_token(api_test_client: TestClient) -> None:
    response = api_test_client.get("/whoami", headers={"Authorization": "Bearer not-a-jwt"})

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE


def test_unsigned_token_is_401_invalid_token(api_test_client: TestClient) -> None:
    header = encode_json_segment({"alg": "none", "typ": "JWT", "kid": SIGNING_KEY_ID})
    payload = encode_json_segment(
        {
            "iss": ISSUER,
            "aud": API_CLIENT_ID,
            "exp": int(time.time()) + 600,
            "tid": TENANT_ID,
            "oid": ALICE_OBJECT_ID,
            "scp": "Notes.ReadWrite",
        }
    )

    response = api_test_client.get(
        "/whoami", headers={"Authorization": f"Bearer {header}.{payload}."}
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE


def test_token_signed_with_the_public_key_as_a_shared_secret_is_401_invalid_token(
    api_test_client: TestClient, private_key: RSAPrivateKey
) -> None:
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    header = encode_json_segment({"alg": "HS256", "typ": "JWT", "kid": SIGNING_KEY_ID})
    payload = encode_json_segment({"iss": ISSUER, "aud": API_CLIENT_ID, "tid": TENANT_ID})
    hmac_algorithm = jwt.algorithms.HMACAlgorithm(jwt.algorithms.HMACAlgorithm.SHA256)
    signature = hmac_algorithm.sign(f"{header}.{payload}".encode(), public_key_pem)
    token = f"{header}.{payload}.{encode_segment(signature)}"

    response = api_test_client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE


def test_token_signed_by_another_key_is_401_invalid_token(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    other_private_key: RSAPrivateKey,
) -> None:
    response = api_test_client.get(
        "/whoami", headers=build_auth_headers(signing_private_key=other_private_key)
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE


@pytest.mark.parametrize(
    "token_overrides",
    [
        pytest.param({"key_id": "unknown"}, id="unknown-key-id"),
        pytest.param(
            {"signing_private_key": "s" * 32, "algorithm": "HS256"}, id="symmetric-algorithm"
        ),
        pytest.param({"iss": f"https://sts.windows.net/{TENANT_ID}/"}, id="v1-issuer"),
        pytest.param(
            {"iss": f"https://login.example/{OTHER_TENANT_ID}/v2.0"}, id="issuer-of-other-tenant"
        ),
        pytest.param({"tid": OTHER_TENANT_ID}, id="tenant-claim-mismatch"),
        pytest.param({"tid": 5}, id="tenant-claim-not-a-string"),
        pytest.param({"omitted_claims": ("tid",)}, id="no-tenant-claim"),
        pytest.param({"aud": DEMO_CLIENT_ID}, id="audience-of-other-client"),
        pytest.param({"aud": f"api://{API_CLIENT_ID}"}, id="v1-audience-form"),
        pytest.param({"aud": [API_CLIENT_ID, DEMO_CLIENT_ID]}, id="audience-list"),
        pytest.param({"omitted_claims": ("aud",)}, id="no-audience"),
        pytest.param({"exp": int(time.time()) - 600}, id="expired"),
        pytest.param({"exp": int(time.time()) - 65}, id="expired-outside-the-tolerance"),
        pytest.param({"nbf": int(time.time()) + 600}, id="not-yet-valid"),
        pytest.param({"nbf": int(time.time()) + 65}, id="not-yet-valid-outside-the-tolerance"),
        pytest.param({"iat": int(time.time()) + 600}, id="issued-in-the-future"),
        pytest.param({"omitted_claims": ("exp",)}, id="no-expiry"),
        pytest.param({"omitted_claims": ("oid",)}, id="no-object-id"),
        pytest.param({"oid": ""}, id="empty-object-id"),
        pytest.param({"oid": 5}, id="object-id-not-a-string"),
    ],
)
def test_unacceptable_token_is_401_invalid_token(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    token_overrides: dict[str, Any],
) -> None:
    response = api_test_client.get("/whoami", headers=build_auth_headers(**token_overrides))

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE


@pytest.mark.parametrize(
    "token_overrides",
    [
        pytest.param({"exp": int(time.time()) - 50}, id="expired-inside-the-tolerance"),
        pytest.param({"nbf": int(time.time()) + 50}, id="not-yet-valid-inside-the-tolerance"),
        pytest.param({"omitted_claims": ("nbf", "iat")}, id="no-optional-time-claims"),
    ],
)
def test_token_inside_the_clock_tolerance_is_200(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    token_overrides: dict[str, Any],
) -> None:
    response = api_test_client.get("/whoami", headers=build_auth_headers(**token_overrides))

    assert response.status_code == 200


def test_listed_client_is_200(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory
) -> None:
    app.dependency_overrides[get_settings] = lambda: build_settings(
        allowed_client_ids=f" {DEMO_CLIENT_ID.upper()} , {OTHER_CLIENT_ID}"
    )

    response = api_test_client.get("/whoami", headers=build_auth_headers())

    assert response.status_code == 200


@pytest.mark.parametrize(
    "token_overrides",
    [
        pytest.param({"azp": OTHER_CLIENT_ID}, id="other-client"),
        pytest.param({"azp": "not-a-client-id"}, id="client-claim-not-an-id"),
        pytest.param({"azp": DEMO_CLIENT_ID.replace("-", "")}, id="client-claim-without-hyphens"),
        pytest.param({"azp": f"{{{DEMO_CLIENT_ID}}}"}, id="client-claim-in-braces"),
        pytest.param({"omitted_claims": ("azp",)}, id="no-client-claim"),
        pytest.param({"azp": OTHER_CLIENT_ID, "scp": "Other.Scope"}, id="other-client-no-scope"),
    ],
)
def test_unlisted_client_is_403_without_a_challenge(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    token_overrides: dict[str, Any],
) -> None:
    app.dependency_overrides[get_settings] = lambda: build_settings(
        allowed_client_ids=DEMO_CLIENT_ID
    )

    response = api_test_client.get("/whoami", headers=build_auth_headers(**token_overrides))

    assert response.status_code == 403
    assert "WWW-Authenticate" not in response.headers


def test_any_client_is_200_without_an_allow_list(
    api_test_client: TestClient, build_auth_headers: AuthHeadersFactory
) -> None:
    response = api_test_client.get("/whoami", headers=build_auth_headers(azp=OTHER_CLIENT_ID))

    assert response.status_code == 200
