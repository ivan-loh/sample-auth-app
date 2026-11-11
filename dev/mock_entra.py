import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any

import jwt
from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import APIRouter, Depends, FastAPI, Form, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.auth import SIGNING_ALGORITHM
from app.config import Settings, SettingsDep

TOKEN_LIFETIME_SECONDS = 3600
SIGNING_KEY_ID_LENGTH = 16
SIGN_IN_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})
DEFAULT_USERNAME = "demo.user@example.com"


class MockSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    demo_client_secret: str
    api_app_id_uri: str = ""


class AuthorizeParams(BaseModel):
    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    response_type: str = ""
    code_challenge_method: str = ""
    state: str | None = None
    nonce: str | None = None
    login_hint: str | None = None


class TokenForm(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str = ""
    code: str = ""
    redirect_uri: str = ""
    code_verifier: str = ""
    refresh_token: str = ""


class TokenResponse(BaseModel):
    token_type: str
    expires_in: int
    scope: str
    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None


@dataclass(frozen=True)
class MockUser:
    object_id: str
    name: str
    username: str


@dataclass(frozen=True)
class Grant:
    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: tuple[str, ...]
    nonce: str | None
    user: MockUser


class GrantStore:
    def __init__(self) -> None:
        self.grants_by_code: dict[str, Grant] = {}
        self.grants_by_refresh_token: dict[str, Grant] = {}


class MockOAuthError(Exception):
    def __init__(self, status_code: int, error: str, error_description: str) -> None:
        self.status_code = status_code
        self.error = error
        self.error_description = error_description


def compute_signing_key_id(private_key: RSAPrivateKey) -> str:
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_key_der).hexdigest()[:SIGNING_KEY_ID_LENGTH]


PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SIGNING_KEY_ID = compute_signing_key_id(PRIVATE_KEY)

grant_store = GrantStore()


@lru_cache
def get_mock_settings() -> MockSettings:
    return MockSettings()


MockSettingsDep = Annotated[MockSettings, Depends(get_mock_settings)]


def require_known_tenant(tenant_id: str, settings: SettingsDep) -> None:
    if tenant_id.lower() != str(settings.tenant_id):
        raise MockOAuthError(status.HTTP_400_BAD_REQUEST, "invalid_request", "Unknown tenant")


def get_api_scope_prefix(settings: SettingsDep, mock_settings: MockSettingsDep) -> str:
    app_id_uri = mock_settings.api_app_id_uri or f"api://{settings.api_client_id}"
    return f"{app_id_uri}/"


ApiScopePrefixDep = Annotated[str, Depends(get_api_scope_prefix)]


def build_mock_user(login_hint: str | None) -> MockUser:
    username = login_hint or DEFAULT_USERNAME
    return MockUser(
        object_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, username.lower())),
        name=username.split("@")[0].replace(".", " ").title(),
        username=username,
    )


def sign_token(claims: dict[str, Any], settings: Settings) -> str:
    issued_at = int(time.time())
    standard_claims = {
        "iss": settings.issuer,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + TOKEN_LIFETIME_SECONDS,
        "ver": "2.0",
    }
    return jwt.encode(
        {**standard_claims, **claims},
        PRIVATE_KEY,
        algorithm=SIGNING_ALGORITHM,
        headers={"kid": SIGNING_KEY_ID},
    )


def build_token_response(grant: Grant, settings: Settings) -> TokenResponse:
    api_scopes = [scope for scope in grant.scopes if scope not in SIGN_IN_SCOPES]
    user_claims = {
        "tid": str(settings.tenant_id),
        "oid": grant.user.object_id,
        "sub": grant.user.object_id,
        "name": grant.user.name,
        "preferred_username": grant.user.username,
    }
    access_claims = {
        **user_claims,
        "aud": str(settings.api_client_id),
        "azp": grant.client_id,
        "scp": " ".join(scope.rsplit("/", 1)[-1] for scope in api_scopes),
    }
    token_response = TokenResponse(
        token_type="Bearer",
        expires_in=TOKEN_LIFETIME_SECONDS,
        scope=" ".join(api_scopes),
        access_token=sign_token(access_claims, settings),
    )

    if "openid" in grant.scopes:
        id_claims = {**user_claims, "aud": grant.client_id}
        if grant.nonce:
            id_claims["nonce"] = grant.nonce
        token_response.id_token = sign_token(id_claims, settings)

    if "offline_access" in grant.scopes:
        refresh_token = secrets.token_urlsafe(32)
        grant_store.grants_by_refresh_token[refresh_token] = grant
        token_response.refresh_token = refresh_token

    return token_response


router = APIRouter(prefix="/{tenant_id}", dependencies=[Depends(require_known_tenant)])


@router.get("/discovery/v2.0/keys")
def read_signing_keys() -> dict[str, list[dict[str, Any]]]:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key(), as_dict=True)
    return {"keys": [{**jwk, "kid": SIGNING_KEY_ID, "use": "sig", "alg": SIGNING_ALGORITHM}]}


@router.get("/oauth2/v2.0/authorize")
def authorize(
    params: Annotated[AuthorizeParams, Query()], api_scope_prefix: ApiScopePrefixDep
) -> RedirectResponse:
    if params.response_type != "code" or params.code_challenge_method != "S256":
        raise MockOAuthError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "Use response_type=code and code_challenge_method=S256",
        )

    scopes = tuple(params.scope.split())
    api_scopes = [scope for scope in scopes if scope not in SIGN_IN_SCOPES]
    if not all(scope.startswith(api_scope_prefix) for scope in api_scopes):
        raise MockOAuthError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_scope",
            f"Each API scope must start with {api_scope_prefix}",
        )

    authorization_code = secrets.token_urlsafe(24)
    grant_store.grants_by_code[authorization_code] = Grant(
        client_id=params.client_id,
        redirect_uri=params.redirect_uri,
        code_challenge=params.code_challenge,
        scopes=scopes,
        nonce=params.nonce,
        user=build_mock_user(params.login_hint),
    )

    callback_params = [("code", authorization_code)]
    if params.state:
        callback_params.append(("state", params.state))
    return RedirectResponse(
        url=add_params_to_uri(params.redirect_uri, callback_params),
        status_code=status.HTTP_302_FOUND,
    )


@router.post("/oauth2/v2.0/token", response_model_exclude_none=True)
def exchange_grant(
    form: Annotated[TokenForm, Form()], settings: SettingsDep, mock_settings: MockSettingsDep
) -> TokenResponse:
    expected_client_secret = mock_settings.demo_client_secret.encode()
    if not secrets.compare_digest(form.client_secret.encode(), expected_client_secret):
        raise MockOAuthError(status.HTTP_401_UNAUTHORIZED, "invalid_client", "Wrong client secret")

    if form.grant_type == "authorization_code":
        grant = grant_store.grants_by_code.pop(form.code, None)
        if grant is None:
            raise MockOAuthError(
                status.HTTP_400_BAD_REQUEST, "invalid_grant", "Unknown or used code"
            )
        if (
            grant.client_id != form.client_id
            or grant.redirect_uri != form.redirect_uri
            or grant.code_challenge != create_s256_code_challenge(form.code_verifier)
        ):
            raise MockOAuthError(
                status.HTTP_400_BAD_REQUEST,
                "invalid_grant",
                "Client, redirect URI or PKCE verifier does not match",
            )
        return build_token_response(grant, settings)

    if form.grant_type == "refresh_token":
        grant = grant_store.grants_by_refresh_token.get(form.refresh_token)
        if grant is None or grant.client_id != form.client_id:
            raise MockOAuthError(
                status.HTTP_400_BAD_REQUEST, "invalid_grant", "Unknown refresh token"
            )
        return build_token_response(grant, settings)

    raise MockOAuthError(
        status.HTTP_400_BAD_REQUEST,
        "unsupported_grant_type",
        "Use authorization_code or refresh_token",
    )


app = FastAPI(title="Mock Entra ID (development only)")

app.include_router(router)


@app.exception_handler(MockOAuthError)
async def handle_mock_oauth_error(request: Request, error: MockOAuthError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"error": error.error, "error_description": error.error_description},
    )
