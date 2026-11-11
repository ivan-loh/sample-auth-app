from functools import lru_cache
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import Depends
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError, PyJWKSetError

from app.config import SettingsDep

JWKS_CACHE_LIFESPAN_SECONDS = 24 * 60 * 60
JWKS_REFETCH_COOLDOWN_SECONDS = 30
JWKS_TIMEOUT_SECONDS = 5

JWKS_DOWNLOAD_ERRORS = (PyJWKClientConnectionError, OSError, ValueError)
JWKS_CONTENT_ERRORS = (PyJWKClientError, PyJWKSetError)


class SigningKeysUnavailableError(Exception):
    pass


@lru_cache
def build_jwk_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(
        jwks_url,
        lifespan=JWKS_CACHE_LIFESPAN_SECONDS,
        cooldown_duration=JWKS_REFETCH_COOLDOWN_SECONDS,
        timeout=JWKS_TIMEOUT_SECONDS,
    )


def get_jwk_client(settings: SettingsDep) -> PyJWKClient:
    return build_jwk_client(settings.jwks_url)


JwkClientDep = Annotated[PyJWKClient, Depends(get_jwk_client)]


def has_signing_keys(jwk_client: PyJWKClient) -> bool:
    try:
        jwk_client.get_signing_keys()
    except (*JWKS_DOWNLOAD_ERRORS, *JWKS_CONTENT_ERRORS):
        return False
    return True


def find_signing_key(jwk_client: PyJWKClient, key_id: str) -> RSAPublicKey | None:
    try:
        signing_key = jwk_client.get_signing_key(key_id).key
    except JWKS_DOWNLOAD_ERRORS as error:
        raise SigningKeysUnavailableError from error
    except JWKS_CONTENT_ERRORS as error:
        if has_signing_keys(jwk_client):
            return None
        raise SigningKeysUnavailableError from error
    return signing_key if isinstance(signing_key, RSAPublicKey) else None
