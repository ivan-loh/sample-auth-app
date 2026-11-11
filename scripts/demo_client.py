import argparse
import sys
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx2
import jwt
from authlib.common.errors import AuthlibBaseError
from authlib.common.security import generate_token
from authlib.integrations.httpx_client import OAuth2Client
from pydantic_settings import BaseSettings, SettingsConfigDict

REDIRECT_PORT = 8765
REDIRECT_PATH = "/callback"
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}{REDIRECT_PATH}"
SIGN_IN_SCOPES = ("openid", "profile", "email", "offline_access")
API_SCOPE_NAMES = ("Notes.Read", "Notes.ReadWrite")
SIGNING_ALGORITHM = "RS256"
REQUIRED_ID_TOKEN_CLAIMS = ("exp", "iat", "iss", "aud", "sub")
CODE_VERIFIER_LENGTH = 64
NONCE_LENGTH = 32


class DemoSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    tenant_id: str
    api_client_id: str
    demo_client_id: str
    demo_client_secret: str
    authority_base_url: str = "https://login.microsoftonline.com"
    api_base_url: str = "http://localhost:8000"
    api_app_id_uri: str = ""

    @property
    def authority_url(self) -> str:
        return f"{self.authority_base_url.rstrip('/')}/{self.tenant_id}"

    @property
    def authorize_url(self) -> str:
        return f"{self.authority_url}/oauth2/v2.0/authorize"

    @property
    def token_url(self) -> str:
        return f"{self.authority_url}/oauth2/v2.0/token"

    @property
    def jwks_url(self) -> str:
        return f"{self.authority_url}/discovery/v2.0/keys"

    @property
    def issuer(self) -> str:
        return f"{self.authority_url}/v2.0"

    @property
    def scope(self) -> str:
        app_id_uri = self.api_app_id_uri or f"api://{self.api_client_id}"
        api_scopes = [f"{app_id_uri}/{scope_name}" for scope_name in API_SCOPE_NAMES]
        return " ".join([*SIGN_IN_SCOPES, *api_scopes])


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    nonce: str
    code_verifier: str


class DemoError(Exception):
    pass


def build_oauth_client(settings: DemoSettings) -> OAuth2Client:
    return OAuth2Client(
        client_id=settings.demo_client_id,
        client_secret=settings.demo_client_secret,
        scope=settings.scope,
        redirect_uri=REDIRECT_URI,
        code_challenge_method="S256",
        token_endpoint_auth_method="client_secret_post",
    )


def build_authorization_request(
    oauth_client: OAuth2Client, settings: DemoSettings, login_hint: str | None
) -> AuthorizationRequest:
    code_verifier = generate_token(CODE_VERIFIER_LENGTH)
    nonce = generate_token(NONCE_LENGTH)
    extra_params = {"login_hint": login_hint} if login_hint else {}
    url, state = oauth_client.create_authorization_url(
        settings.authorize_url,
        code_verifier=code_verifier,
        nonce=nonce,
        **extra_params,
    )
    return AuthorizationRequest(url=url, state=state, nonce=nonce, code_verifier=code_verifier)


def wait_for_callback_url() -> str:
    callback_urls: list[str] = []

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if urlparse(self.path).path != REDIRECT_PATH:
                self.send_error(404)
                return
            callback_urls.append(f"http://localhost:{REDIRECT_PORT}{self.path}")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Sign-in complete. You can close this tab.\n")

        def log_message(self, format: str, *args: Any) -> None:
            return

    with HTTPServer(("localhost", REDIRECT_PORT), CallbackHandler) as server:
        while not callback_urls:
            server.handle_request()
    return callback_urls[0]


def raise_for_callback_error(callback_url: str) -> None:
    callback_params = parse_qs(urlparse(callback_url).query)
    if "error" in callback_params:
        error = callback_params["error"][0]
        error_description = callback_params.get("error_description", [""])[0]
        raise DemoError(f"Sign-in failed: {error} {error_description}".strip())


def require_token(tokens: dict[str, Any], token_name: str) -> str:
    token = tokens.get(token_name)
    if not isinstance(token, str):
        raise DemoError(f"The token response has no {token_name}")
    return token


def validate_id_token(settings: DemoSettings, id_token: str, nonce: str) -> dict[str, Any]:
    signing_key = jwt.PyJWKClient(settings.jwks_url).get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=[SIGNING_ALGORITHM],
        audience=settings.demo_client_id,
        issuer=settings.issuer,
        options={"require": list(REQUIRED_ID_TOKEN_CLAIMS)},
    )
    if claims.get("nonce") != nonce:
        raise DemoError("The nonce does not match")
    return claims


def print_response(title: str, response: httpx2.Response) -> None:
    print(f"\n{title}\n  HTTP {response.status_code}  {response.text}")


def call_api(oauth_client: OAuth2Client, settings: DemoSettings) -> None:
    whoami_url = f"{settings.api_base_url}/whoami"
    notes_url = f"{settings.api_base_url}/notes"
    note = {"text": "Hello from the demo client"}
    print_response("GET /whoami", oauth_client.get(whoami_url))
    print_response("POST /notes", oauth_client.post(notes_url, json=note))
    print_response("GET /notes", oauth_client.get(notes_url))
    print_response("GET /whoami with no token", httpx2.get(whoami_url))


def run_demo(*, open_browser: bool, login_hint: str | None) -> None:
    settings = DemoSettings()

    with build_oauth_client(settings) as oauth_client:
        authorization_request = build_authorization_request(oauth_client, settings, login_hint)
        print(f"Sign in at:\n  {authorization_request.url}", flush=True)
        if open_browser:
            webbrowser.open(authorization_request.url)

        callback_url = wait_for_callback_url()
        raise_for_callback_error(callback_url)

        tokens = oauth_client.fetch_token(
            settings.token_url,
            authorization_response=callback_url,
            state=authorization_request.state,
            code_verifier=authorization_request.code_verifier,
        )
        print(f"\nGranted scopes: {tokens.get('scope')}")

        id_token = require_token(tokens, "id_token")
        refresh_token = require_token(tokens, "refresh_token")
        id_claims = validate_id_token(settings, id_token, authorization_request.nonce)
        print(
            f"Signed in: tenant_id={id_claims.get('tid')} object_id={id_claims.get('oid')} "
            f"username={id_claims.get('preferred_username')}"
        )

        call_api(oauth_client, settings)

        oauth_client.refresh_token(settings.token_url, refresh_token=refresh_token)
        whoami_response = oauth_client.get(f"{settings.api_base_url}/whoami")
        print_response("GET /whoami after refresh", whoami_response)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign in, get tokens, call the API and refresh the access token."
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print the sign-in URL and do not open a browser",
    )
    parser.add_argument("--login-hint", help="the account to sign in")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        run_demo(open_browser=not arguments.no_browser, login_hint=arguments.login_hint)
    except (DemoError, AuthlibBaseError, jwt.PyJWTError, httpx2.HTTPError) as error:
        print(f"Demo failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
