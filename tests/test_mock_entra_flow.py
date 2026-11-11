import io
import urllib.request
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx2
import jwt
import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.signing_keys import build_jwk_client
from dev.mock_entra import MockSettings, get_mock_settings
from dev.mock_entra import app as mock_entra_app
from tests.helpers import (
    ALICE_USERNAME,
    API_CLIENT_ID,
    BOB_USERNAME,
    DEMO_CLIENT_ID,
    ISSUER,
    TENANT_ID,
    build_settings,
)

DEMO_CLIENT_SECRET = "test-secret"
REDIRECT_URI = "http://localhost:8765/callback"
CODE_VERIFIER = "v" * 64
API_SCOPE = f"api://{API_CLIENT_ID}/Notes.Read api://{API_CLIENT_ID}/Notes.ReadWrite"
SCOPE = f"openid profile email offline_access {API_SCOPE}"
AUTHORIZE_PATH = f"/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_PATH = f"/{TENANT_ID}/oauth2/v2.0/token"


def build_access_token_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def build_refresh_form(issued_refresh_token: str, **form_overrides: str) -> dict[str, str]:
    return {
        "grant_type": "refresh_token",
        "client_id": DEMO_CLIENT_ID,
        "client_secret": DEMO_CLIENT_SECRET,
        "refresh_token": issued_refresh_token,
        **form_overrides,
    }


@pytest.fixture
def entra_test_client() -> Iterator[TestClient]:
    mock_entra_app.dependency_overrides[get_settings] = lambda: build_settings()
    mock_entra_app.dependency_overrides[get_mock_settings] = lambda: MockSettings(
        _env_file=None, demo_client_secret=DEMO_CLIENT_SECRET
    )
    yield TestClient(mock_entra_app, follow_redirects=False)
    mock_entra_app.dependency_overrides.clear()


@pytest.fixture
def api_test_client(
    monkeypatch: pytest.MonkeyPatch, entra_test_client: TestClient
) -> Iterator[TestClient]:
    def open_url(opener: Any, request: Any, data: Any = None, timeout: Any = None) -> io.BytesIO:
        return io.BytesIO(entra_test_client.get(urlparse(request.full_url).path).content)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", open_url)
    build_jwk_client.cache_clear()
    app.dependency_overrides[get_settings] = lambda: build_settings()
    yield TestClient(app)
    app.dependency_overrides.clear()
    build_jwk_client.cache_clear()


def request_authorization(entra_test_client: TestClient, **param_overrides: str) -> httpx2.Response:
    params = {
        "client_id": DEMO_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": "state-value",
        "nonce": "nonce-value",
        "code_challenge": create_s256_code_challenge(CODE_VERIFIER),
        "code_challenge_method": "S256",
        **param_overrides,
    }
    return entra_test_client.get(AUTHORIZE_PATH, params=params)


def authorize(entra_test_client: TestClient, **param_overrides: str) -> dict[str, str]:
    response = request_authorization(entra_test_client, **param_overrides)
    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    return {name: values[0] for name, values in parse_qs(location.query).items()}


def exchange_code(
    entra_test_client: TestClient, authorization_code: str, **form_overrides: str
) -> httpx2.Response:
    form = {
        "grant_type": "authorization_code",
        "client_id": DEMO_CLIENT_ID,
        "client_secret": DEMO_CLIENT_SECRET,
        "code": authorization_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": CODE_VERIFIER,
        **form_overrides,
    }
    return entra_test_client.post(TOKEN_PATH, data=form)


def test_sign_in_then_api_call_returns_the_identity(
    entra_test_client: TestClient, api_test_client: TestClient
) -> None:
    callback_params = authorize(entra_test_client, login_hint=ALICE_USERNAME)
    assert callback_params["state"] == "state-value"

    tokens = exchange_code(entra_test_client, callback_params["code"]).json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == API_SCOPE

    id_claims = jwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert id_claims["iss"] == ISSUER
    assert id_claims["aud"] == DEMO_CLIENT_ID
    assert id_claims["nonce"] == "nonce-value"

    response = api_test_client.get(
        "/whoami", headers=build_access_token_headers(tokens["access_token"])
    )
    assert response.status_code == 200
    assert response.json() == {
        "tenant_id": TENANT_ID,
        "object_id": id_claims["oid"],
        "name": "Alice",
        "username": ALICE_USERNAME,
        "scopes": ["Notes.Read", "Notes.ReadWrite"],
        "client_id": DEMO_CLIENT_ID,
    }


def test_refresh_token_returns_a_new_access_token(
    entra_test_client: TestClient, api_test_client: TestClient
) -> None:
    tokens = exchange_code(entra_test_client, authorize(entra_test_client)["code"]).json()

    refreshed = entra_test_client.post(TOKEN_PATH, data=build_refresh_form(tokens["refresh_token"]))

    assert refreshed.status_code == 200
    assert refreshed.json()["refresh_token"] != tokens["refresh_token"]
    response = api_test_client.get(
        "/whoami", headers=build_access_token_headers(refreshed.json()["access_token"])
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "form_overrides",
    [
        pytest.param({"refresh_token": "unknown"}, id="unknown-refresh-token"),
        pytest.param({"client_id": "other-client"}, id="refresh-token-of-other-client"),
    ],
)
def test_bad_refresh_request_is_400_invalid_grant(
    entra_test_client: TestClient, form_overrides: dict[str, str]
) -> None:
    tokens = exchange_code(entra_test_client, authorize(entra_test_client)["code"]).json()

    response = entra_test_client.post(
        TOKEN_PATH, data=build_refresh_form(tokens["refresh_token"], **form_overrides)
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_read_only_grant_cannot_write(
    entra_test_client: TestClient, api_test_client: TestClient
) -> None:
    callback_params = authorize(entra_test_client, scope=f"openid api://{API_CLIENT_ID}/Notes.Read")
    tokens = exchange_code(entra_test_client, callback_params["code"]).json()
    headers = build_access_token_headers(tokens["access_token"])

    assert "refresh_token" not in tokens
    assert api_test_client.get("/notes", headers=headers).status_code == 200
    assert api_test_client.post("/notes", headers=headers, json={"text": "x"}).status_code == 403


def test_grant_without_openid_has_no_id_token(entra_test_client: TestClient) -> None:
    callback_params = authorize(entra_test_client, scope=f"api://{API_CLIENT_ID}/Notes.Read")

    tokens = exchange_code(entra_test_client, callback_params["code"]).json()

    assert set(tokens) == {"token_type", "expires_in", "scope", "access_token"}


def test_different_users_get_different_object_ids(entra_test_client: TestClient) -> None:
    object_ids = set()
    for login_hint in (ALICE_USERNAME, BOB_USERNAME):
        authorization_code = authorize(entra_test_client, login_hint=login_hint)["code"]
        tokens = exchange_code(entra_test_client, authorization_code).json()
        claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
        object_ids.add(claims["oid"])

    assert len(object_ids) == 2


@pytest.mark.parametrize(
    ("form_overrides", "expected_status", "expected_error"),
    [
        pytest.param({"client_secret": "wrong"}, 401, "invalid_client", id="wrong-secret"),
        pytest.param({"client_secret": "sécret"}, 401, "invalid_client", id="non-ascii-secret"),
        pytest.param({"code_verifier": "w" * 64}, 400, "invalid_grant", id="wrong-verifier"),
        pytest.param(
            {"redirect_uri": "http://localhost:1/x"}, 400, "invalid_grant", id="wrong-redirect"
        ),
        pytest.param({"client_id": "other-client"}, 400, "invalid_grant", id="wrong-client"),
        pytest.param({"code": "unknown"}, 400, "invalid_grant", id="unknown-code"),
        pytest.param(
            {"grant_type": "password"}, 400, "unsupported_grant_type", id="unsupported-grant"
        ),
    ],
)
def test_bad_code_request_is_refused_with_an_oauth_error(
    entra_test_client: TestClient,
    form_overrides: dict[str, str],
    expected_status: int,
    expected_error: str,
) -> None:
    authorization_code = authorize(entra_test_client)["code"]

    response = exchange_code(entra_test_client, authorization_code, **form_overrides)

    assert response.status_code == expected_status
    assert response.json()["error"] == expected_error


def test_used_code_is_400_invalid_grant(entra_test_client: TestClient) -> None:
    authorization_code = authorize(entra_test_client)["code"]

    first_response = exchange_code(entra_test_client, authorization_code)
    second_response = exchange_code(entra_test_client, authorization_code)

    assert first_response.status_code == 200
    assert second_response.status_code == 400
    assert second_response.json()["error"] == "invalid_grant"


def test_authorize_without_s256_pkce_is_400_invalid_request(
    entra_test_client: TestClient,
) -> None:
    response = request_authorization(
        entra_test_client, code_challenge="plain-challenge", code_challenge_method="plain"
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param("openid https://other-api.example.com/User.Read", id="scope-of-other-api"),
        pytest.param("openid Notes.Read", id="scope-without-the-application-id-uri"),
    ],
)
def test_authorize_with_a_scope_of_another_api_is_400_invalid_scope(
    entra_test_client: TestClient, scope: str
) -> None:
    response = request_authorization(entra_test_client, scope=scope)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_authorize_keeps_the_query_of_the_redirect_uri(entra_test_client: TestClient) -> None:
    response = request_authorization(entra_test_client, redirect_uri=f"{REDIRECT_URI}?tab=1")

    callback_params = parse_qs(urlparse(response.headers["location"]).query)

    assert response.status_code == 302
    assert callback_params["tab"] == ["1"]
    assert callback_params["state"] == ["state-value"]


def test_unknown_tenant_is_400_invalid_request(entra_test_client: TestClient) -> None:
    response = entra_test_client.get("/other-tenant/discovery/v2.0/keys")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
