from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from jwt import PyJWKClient

from app.config import Settings, SettingsDep
from app.signing_keys import JwkClientDep, SigningKeysUnavailableError, find_signing_key

SIGNING_ALGORITHM = "RS256"
CLOCK_TOLERANCE_SECONDS = 60
RETRY_AFTER_SECONDS = 5

AUTH_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {"description": "The access token is missing or not valid"},
    status.HTTP_403_FORBIDDEN: {"description": "The scope is missing or the client is not allowed"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "The signing keys are not available"},
}

UserKey = tuple[str, str]


class Scope(StrEnum):
    NOTES_READ = "Notes.Read"
    NOTES_READ_WRITE = "Notes.ReadWrite"


IMPLIED_SCOPES: dict[str, frozenset[str]] = {
    Scope.NOTES_READ_WRITE: frozenset({Scope.NOTES_READ}),
}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    object_id: str
    name: str | None
    username: str | None
    scopes: frozenset[str]
    client_id: str | None

    @property
    def user_key(self) -> UserKey:
        return (self.tenant_id, self.object_id)


def build_invalid_token_error(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def build_insufficient_scope_error(required_scope: str) -> HTTPException:
    challenge = f'Bearer error="insufficient_scope", scope="{required_scope}"'
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Missing scope",
        headers={"WWW-Authenticate": challenge},
    )


def build_client_not_allowed_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Client application is not allowed",
    )


def build_signing_keys_unavailable_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Signing keys are unavailable",
        headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
    )


def find_string_claim(claims: dict[str, Any], claim_name: str) -> str | None:
    value = claims.get(claim_name)
    return value if isinstance(value, str) and value else None


def add_implied_scopes(granted_scopes: frozenset[str]) -> frozenset[str]:
    implied_scopes = (IMPLIED_SCOPES.get(scope, frozenset()) for scope in granted_scopes)
    return granted_scopes.union(*implied_scopes)


def validate_access_token(token: str, settings: Settings, jwk_client: PyJWKClient) -> Principal:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise build_invalid_token_error("Malformed token") from None

    key_id = header.get("kid")
    if header.get("alg") != SIGNING_ALGORITHM or not isinstance(key_id, str):
        raise build_invalid_token_error("Unsupported token header")

    try:
        signing_key = find_signing_key(jwk_client, key_id)
    except SigningKeysUnavailableError:
        raise build_signing_keys_unavailable_error() from None
    if signing_key is None:
        raise build_invalid_token_error("Unknown signing key")

    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=[SIGNING_ALGORITHM],
            audience=str(settings.api_client_id),
            issuer=settings.issuer,
            leeway=CLOCK_TOLERANCE_SECONDS,
            options={"require": ["exp", "iss", "aud"], "strict_aud": True},
        )
    except jwt.PyJWTError as error:
        raise build_invalid_token_error(f"Token refused: {type(error).__name__}") from None

    tenant_id = find_string_claim(claims, "tid")
    object_id = find_string_claim(claims, "oid")
    scope_claim = find_string_claim(claims, "scp") or ""

    if tenant_id != str(settings.tenant_id):
        raise build_invalid_token_error("Wrong tenant")
    if object_id is None:
        raise build_invalid_token_error("Token has no user")

    return Principal(
        tenant_id=tenant_id,
        object_id=object_id,
        name=find_string_claim(claims, "name"),
        username=find_string_claim(claims, "preferred_username"),
        scopes=frozenset(scope for scope in scope_claim.split(" ") if scope),
        client_id=find_string_claim(claims, "azp"),
    )


bearer_scheme = HTTPBearer()

BearerCredentialsDep = Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]


def get_current_principal(
    security_scopes: SecurityScopes,
    credentials: BearerCredentialsDep,
    settings: SettingsDep,
    jwk_client: JwkClientDep,
) -> Principal:
    principal = validate_access_token(credentials.credentials, settings, jwk_client)

    if not settings.is_client_allowed(principal.client_id):
        raise build_client_not_allowed_error()
    if not add_implied_scopes(principal.scopes).issuperset(security_scopes.scopes):
        raise build_insufficient_scope_error(security_scopes.scope_str)
    return principal


ReadPrincipalDep = Annotated[
    Principal,
    Security(get_current_principal, scopes=[Scope.NOTES_READ]),
]
WritePrincipalDep = Annotated[
    Principal,
    Security(get_current_principal, scopes=[Scope.NOTES_READ_WRITE]),
]
