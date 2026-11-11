from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import get_settings
from app.main import app
from app.signing_keys import build_jwk_client
from tests.helpers import (
    API_CLIENT_ID,
    DEMO_CLIENT_ID,
    ISSUER,
    JWKS_URL,
    OTHER_CLIENT_ID,
    TENANT_ID,
    build_settings,
)

REMOTE_AUTHORITY = "login.example.com"


@pytest.fixture
def startup_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    monkeypatch.setenv("TENANT_ID", TENANT_ID)
    monkeypatch.setenv("API_CLIENT_ID", API_CLIENT_ID)
    monkeypatch.setenv("AUTHORITY_BASE_URL", f"https://{REMOTE_AUTHORITY}")
    monkeypatch.setenv("ALLOWED_CLIENT_IDS", "")
    get_settings.cache_clear()
    build_jwk_client.cache_clear()
    yield monkeypatch
    get_settings.cache_clear()
    build_jwk_client.cache_clear()


def test_settings_build_the_issuer_and_the_jwks_url() -> None:
    settings = build_settings()

    assert settings.issuer == ISSUER
    assert settings.jwks_url == JWKS_URL


@pytest.mark.parametrize(
    "tenant_id",
    [
        pytest.param(TENANT_ID.replace("1", "A"), id="upper-case"),
        pytest.param(f"{{{TENANT_ID}}}", id="braces"),
    ],
)
def test_tenant_id_setting_is_normalized(tenant_id: str) -> None:
    settings = build_settings(tenant_id=tenant_id)

    assert str(settings.tenant_id) == tenant_id.strip("{}").lower()


@pytest.mark.parametrize(
    "authority_base_url",
    [
        pytest.param("http://localhost:4050", id="http-on-localhost"),
        pytest.param("http://127.0.0.1:4050/", id="http-on-loopback-address"),
        pytest.param(f"https://{REMOTE_AUTHORITY}/", id="https-with-trailing-slash"),
    ],
)
def test_authority_base_url_setting_is_accepted(authority_base_url: str) -> None:
    settings = build_settings(authority_base_url=authority_base_url)

    assert settings.authority_base_url == authority_base_url.rstrip("/")


@pytest.mark.parametrize(
    "settings_overrides",
    [
        pytest.param({"allowed_client_ids": ","}, id="allow-list-with-only-a-separator"),
        pytest.param({"allowed_client_ids": f"{DEMO_CLIENT_ID},"}, id="allow-list-ends-with-comma"),
        pytest.param(
            {"allowed_client_ids": f"{DEMO_CLIENT_ID};{OTHER_CLIENT_ID}"},
            id="allow-list-with-wrong-separator",
        ),
        pytest.param({"allowed_client_ids": "my-client"}, id="allow-list-entry-not-an-id"),
        pytest.param({"tenant_id": "tenant.example.com"}, id="tenant-domain-name"),
        pytest.param({"api_client_id": f"api://{API_CLIENT_ID}"}, id="application-id-uri"),
        pytest.param(
            {"authority_base_url": f"http://{REMOTE_AUTHORITY}"}, id="http-on-a-remote-host"
        ),
        pytest.param({"authority_base_url": REMOTE_AUTHORITY}, id="authority-without-scheme"),
        pytest.param(
            {"authority_base_url": f"https://{REMOTE_AUTHORITY}/{TENANT_ID}"},
            id="authority-with-tenant-path",
        ),
        pytest.param({"authority_base_url": ""}, id="empty-authority"),
    ],
)
def test_invalid_setting_is_refused(settings_overrides: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        build_settings(**settings_overrides)


def test_blank_allow_list_setting_is_an_empty_allow_list() -> None:
    assert build_settings(allowed_client_ids="  ").allowed_client_ids == frozenset()


def test_api_starts_with_valid_settings(startup_environment: pytest.MonkeyPatch) -> None:
    with TestClient(app) as api_test_client:
        response = api_test_client.get("/healthz")

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("variable_name", "value"),
    [
        pytest.param("TENANT_ID", "tenant.example.com", id="tenant-domain-name"),
        pytest.param("ALLOWED_CLIENT_IDS", "my-client", id="allow-list-entry-not-an-id"),
        pytest.param("AUTHORITY_BASE_URL", REMOTE_AUTHORITY, id="authority-without-scheme"),
    ],
)
def test_api_does_not_start_with_an_invalid_setting(
    startup_environment: pytest.MonkeyPatch, variable_name: str, value: str
) -> None:
    startup_environment.setenv(variable_name, value)

    with pytest.raises(ValidationError), TestClient(app):
        pass
