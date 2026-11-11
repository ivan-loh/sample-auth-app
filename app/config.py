from functools import lru_cache
from typing import Annotated, Any
from urllib.parse import urlparse
from uuid import UUID

from fastapi import Depends
from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    tenant_id: UUID
    api_client_id: UUID
    authority_base_url: str = "https://login.microsoftonline.com"
    allowed_client_ids: Annotated[frozenset[UUID], NoDecode] = frozenset()

    @field_validator("authority_base_url")
    @classmethod
    def validate_authority_base_url(cls, value: str) -> str:
        url = urlparse(value)
        is_local_http = url.scheme == "http" and url.hostname in LOCAL_HOSTS
        if url.scheme != "https" and not is_local_http:
            raise ValueError("Use an https URL, or an http URL on localhost")
        if not url.hostname or url.path not in ("", "/") or url.query or url.fragment:
            raise ValueError("Use the scheme and the host only")
        return value.rstrip("/")

    @field_validator("allowed_client_ids", mode="before")
    @classmethod
    def split_allowed_client_ids(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if not value.strip():
            return frozenset()
        return [client_id.strip() for client_id in value.split(",")]

    @property
    def authority_url(self) -> str:
        return f"{self.authority_base_url}/{self.tenant_id}"

    @property
    def issuer(self) -> str:
        return f"{self.authority_url}/v2.0"

    @property
    def jwks_url(self) -> str:
        return f"{self.authority_url}/discovery/v2.0/keys"

    def is_client_allowed(self, client_id: str | None) -> bool:
        if not self.allowed_client_ids:
            return True
        return client_id in {
            str(allowed_client_id) for allowed_client_id in self.allowed_client_ids
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]
