import urllib.error
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.testclient import TestClient
from jwt import PyJWKClient

from app.auth import RETRY_AFTER_SECONDS
from app.main import app
from app.signing_keys import (
    JWKS_CACHE_LIFESPAN_SECONDS,
    JWKS_REFETCH_COOLDOWN_SECONDS,
    JWKS_TIMEOUT_SECONDS,
    build_jwk_client,
    get_jwk_client,
)
from tests.helpers import (
    INVALID_TOKEN_CHALLENGE,
    JWKS_URL,
    SIGNING_KEY_ID,
    AuthHeadersFactory,
    FakeJwksEndpoint,
    build_jwk,
    build_jwks,
)

ROTATED_KEY_ID = "rotated-key"
UNREACHABLE_ERROR = urllib.error.URLError("unreachable")


def assert_signing_keys_unavailable(response: httpx2.Response) -> None:
    assert response.status_code == 503
    assert response.headers["Retry-After"] == str(RETRY_AFTER_SECONDS)
    assert "WWW-Authenticate" not in response.headers


def use_jwk_client_without_cooldown() -> None:
    jwk_client = PyJWKClient(JWKS_URL, cooldown_duration=0)
    app.dependency_overrides[get_jwk_client] = lambda: jwk_client


def test_jwk_client_is_built_with_the_documented_limits() -> None:
    jwk_client = build_jwk_client(JWKS_URL)

    assert jwk_client.uri == JWKS_URL
    assert jwk_client.jwk_set_cache is not None
    assert jwk_client.jwk_set_cache.lifespan == JWKS_CACHE_LIFESPAN_SECONDS
    assert jwk_client.cooldown_duration == JWKS_REFETCH_COOLDOWN_SECONDS
    assert jwk_client.timeout == JWKS_TIMEOUT_SECONDS


def test_signing_keys_are_downloaded_one_time_for_many_requests(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
) -> None:
    for _ in range(3):
        assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200

    assert jwks_endpoint.request_count == 1


def test_unknown_key_ids_inside_the_cooldown_are_401_without_a_download(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
) -> None:
    for attempt in range(5):
        response = api_test_client.get(
            "/whoami", headers=build_auth_headers(key_id=f"made-up-{attempt}")
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE

    assert jwks_endpoint.request_count == 1


def test_rotated_key_inside_the_cooldown_is_401_invalid_token(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    other_private_key: RSAPrivateKey,
) -> None:
    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200

    jwks_endpoint.serve_jwks(build_jwks(other_private_key, ROTATED_KEY_ID))
    response = api_test_client.get(
        "/whoami",
        headers=build_auth_headers(signing_private_key=other_private_key, key_id=ROTATED_KEY_ID),
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE


def test_rotated_key_after_the_cooldown_is_200(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    other_private_key: RSAPrivateKey,
) -> None:
    use_jwk_client_without_cooldown()
    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200

    jwks_endpoint.serve_jwks(build_jwks(other_private_key, ROTATED_KEY_ID))
    response = api_test_client.get(
        "/whoami",
        headers=build_auth_headers(signing_private_key=other_private_key, key_id=ROTATED_KEY_ID),
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(UNREACHABLE_ERROR, id="unreachable"),
        pytest.param(TimeoutError("timed out"), id="timeout"),
        pytest.param(ConnectionResetError("reset"), id="connection-reset"),
    ],
)
def test_failed_download_is_503_with_retry_after(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    error: Exception,
) -> None:
    jwks_endpoint.error = error

    assert_signing_keys_unavailable(api_test_client.get("/whoami", headers=build_auth_headers()))


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"<html>proxy login</html>", id="html"),
        pytest.param(b"", id="empty-body"),
        pytest.param(b'{"keys": [', id="truncated-json"),
        pytest.param(b"\xff\xfe", id="invalid-utf-8"),
    ],
)
def test_download_that_is_not_json_is_503_with_retry_after(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    body: bytes,
) -> None:
    jwks_endpoint.body = body

    assert_signing_keys_unavailable(api_test_client.get("/whoami", headers=build_auth_headers()))


@pytest.mark.parametrize(
    "jwks",
    [
        pytest.param({}, id="no-keys-member"),
        pytest.param({"keys": []}, id="empty-key-list"),
        pytest.param({"keys": "abc"}, id="keys-not-a-list"),
        pytest.param({"keys": [None, "oops"]}, id="entries-not-objects"),
        pytest.param(["not", "an", "object"], id="document-not-an-object"),
        pytest.param({"keys": [{"kty": "RSA", "kid": "bad", "e": "AQAB"}]}, id="unusable-key"),
    ],
)
def test_unusable_jwks_document_is_503_with_retry_after(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    jwks: Any,
) -> None:
    jwks_endpoint.serve_jwks(jwks)

    assert_signing_keys_unavailable(api_test_client.get("/whoami", headers=build_auth_headers()))


def test_api_recovers_when_the_download_succeeds_again(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
) -> None:
    jwks_endpoint.error = UNREACHABLE_ERROR
    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 503

    jwks_endpoint.error = None

    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200


def test_cached_signing_keys_stay_valid_when_a_later_download_fails(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
) -> None:
    use_jwk_client_without_cooldown()
    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200

    jwks_endpoint.error = UNREACHABLE_ERROR
    unknown_key_response = api_test_client.get(
        "/whoami", headers=build_auth_headers(key_id=ROTATED_KEY_ID)
    )

    assert_signing_keys_unavailable(unknown_key_response)
    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200


def test_unusable_jwks_entry_does_not_hide_the_usable_signing_keys(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    private_key: RSAPrivateKey,
) -> None:
    jwks_endpoint.serve_jwks(
        {
            "keys": [
                {"kty": "RSA", "kid": "bad", "e": "AQAB"},
                {**build_jwk(private_key, "encryption-key"), "use": "enc"},
                build_jwk(private_key, SIGNING_KEY_ID),
            ]
        }
    )

    assert api_test_client.get("/whoami", headers=build_auth_headers()).status_code == 200
    response = api_test_client.get("/whoami", headers=build_auth_headers(key_id="encryption-key"))
    assert response.status_code == 401


def test_private_key_in_the_jwks_document_is_401_invalid_token(
    api_test_client: TestClient,
    build_auth_headers: AuthHeadersFactory,
    jwks_endpoint: FakeJwksEndpoint,
    private_key: RSAPrivateKey,
) -> None:
    private_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key, as_dict=True)
    jwks_endpoint.serve_jwks({"keys": [{**private_jwk, "kid": SIGNING_KEY_ID, "use": "sig"}]})

    response = api_test_client.get("/whoami", headers=build_auth_headers())

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE
