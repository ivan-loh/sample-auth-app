# App authorization: how to protect a FastAPI API with Entra ID

## 1. Purpose

This document is the design of the sample in this repository.

The sample shows how to protect a FastAPI API with Entra ID. An external platform then calls the
API for a user. This document calls that platform **Acme**.

Read [acme-oauth2.md](acme-oauth2.md) to learn how Acme does its part.

### 1.1 Conventions

- "Must" shows a mandatory rule.
- "Can" shows an option.
- **CAUTION** shows a risk to security or to data.
- **NOTE** gives more information.

### 1.2 Key facts

- The API is an OAuth2 resource server. It does not sign in users. It does not receive passwords.
- Entra ID issues the tokens. Acme sends the tokens. The API validates the tokens.
- Each request must contain an access token from your tenant, for this API, with the correct scope.
- The API identifies the user by two claims: `tid` and `oid`.
- The API accepts one tenant only.

## 2. Terms

| Term | Definition |
|---|---|
| Tenant | The directory of your company in Entra ID |
| App registration | A record in Entra ID that describes one application |
| Registration A | The app registration for the API |
| Registration B | The app registration for the Acme client |
| Access token | A signed token that the client sends to the API with each request |
| ID token | A signed token that tells the client who the user is |
| Refresh token | A token that the client uses to get a new access token |
| Scope | A named permission in an access token |
| Claim | One field in a token |
| Delegated token | An access token that Entra ID issues for a signed-in user |
| App-only token | An access token that Entra ID issues for an application, with no user |
| Signing key | The public key that proves Entra ID signed a token |

## 3. System overview

```
                         ┌──────────────────────────────┐
                         │  Entra ID (your tenant)      │
                         │                              │
                         │  Registration A: the API     │
                         │   exposes scopes             │
                         │    api://<api-id>/Notes.Read │
                         │    api://<api-id>/Notes.ReadWrite
                         │                              │
                         │  Registration B: Acme client │
                         │   client ID + client secret  │
                         │   redirect URI = Acme callback
                         │   permission to request      │
                         │   the scopes of A            │
                         └──────┬───────────────▲───────┘
              signs tokens,     │               │  sign-in, consent,
              publishes keys    │               │  code → tokens
                                ▼               │
 ┌───────────────────────────────────┐    ┌─────┴──────────────────────┐
 │ Your API (FastAPI)   ◄── this repo│    │ Acme                       │
 │                                   │◄───┤                            │
 │  validates each access token      │    │  keeps the user's tokens   │
 │                                   │    │  calls the API as the user │
 │  GET  /healthz   no token         │    └────────────────────────────┘
 │  GET  /whoami    Notes.Read       │        Authorization: Bearer …
 │  GET  /notes     Notes.Read       │
 │  POST /notes     Notes.ReadWrite  │
 └───────────────────────────────────┘
```

Your tenant contains the two app registrations. You own them. You give the client ID and the client secret of
registration B to Acme.

## 4. How a request works

```
 User          Acme                    Entra ID               Your API (FastAPI)
   │             │                        │                          │
   │ Connect     │                        │                          │
   ├────────────►│  redirect ────────────►│                          │
   │             │  (client B, scopes of A│                          │
   │             │   PKCE, state)         │                          │
   │      signs in and consents ─────────►│                          │
   │             │◄──── code ─────────────┤                          │
   │             │  code+verifier+secret ►│                          │
   │             │◄─ ID token ────────────┤  identifies the user     │
   │             │◄─ access token ────────┤  audience = the API      │
   │             │◄─ refresh token ───────┤                          │
   │             │                        │                          │
   │ "who am I?" │                        │                          │
   ├────────────►│  GET /whoami, Bearer access token ───────────────►│
   │             │                        │◄── get signing keys ─────┤ (cached)
   │             │                        │                          │ validate token
   │             │◄──── 200 {tenant_id, object_id, name, ────────────┤
   │             │           username, scopes, client_id}            │
   │◄────────────┤                        │                          │
```

The sequence is as follows:

1. The user starts a connection in Acme.
2. Acme sends the user to Entra ID.
3. The user signs in and gives consent.
4. Entra ID sends a one-time code to Acme.
5. Acme exchanges the code, the PKCE verifier and the client secret for tokens.
6. Acme calls the API with the access token.
7. The API validates the access token and sends the response.

Steps 1 to 5 occur one time for each user. Steps 6 and 7 occur for each request.

Acme requests these scopes:

- The sign-in scopes: `openid profile email offline_access`.
- The scopes of the API.

**NOTE:** The `profile` scope makes Entra ID put `oid` and `tid` in the ID token.

**NOTE:** One token request can contain the scopes of one API only. Thus Acme requests the scopes of this
API only. It does not request the scopes of a different API in the same request.

## 5. Procedure: set up Entra ID

### 5.1 Create registration A (the API)

1. Register an application.
2. Select "Accounts in this organizational directory only".
3. Open **Expose an API**.
4. Set the Application ID URI to `api://<api-client-id>`.
5. Add the delegated scope `Notes.Read`.
6. Add the delegated scope `Notes.ReadWrite`.
7. For each scope, set "Who can consent" to "Admins and users".
8. Set the state of each scope to Enabled.
9. Open the app manifest.
10. Set `api.requestedAccessTokenVersion` to `2`.

**NOTE:** The older manifest format shows this property as `accessTokenAcceptedVersion`.

**CAUTION:** If you do not do step 10, Entra ID issues v1.0 tokens. The issuer and the audience of a v1.0 token are
different. The API refuses v1.0 tokens.

Registration A has no client secret and no redirect URI. It defines the API and its scopes only.

### 5.2 Create registration B (the Acme client)

1. Register a second application.
2. Select "Accounts in this organizational directory only".
3. Add a **Web** platform.
4. Add the redirect URI that Acme gives you.
5. For the local demo, add the redirect URI `http://localhost:8765/callback`.
6. Create a client secret.
7. Record the value of the client secret.
8. Open **API permissions**.
9. Add the delegated permission `Notes.Read` from registration A.
10. Add the delegated permission `Notes.ReadWrite` from registration A.
11. Grant admin consent.

**NOTE:** Step 11 is mandatory if your tenant limits user consent. As an alternative, add the client ID of B to
"Authorized client applications" in registration A, for the two scopes.

**CAUTION:** In a production tenant, use a different app registration for the local demo.

### 5.3 Give these values to Acme

| Value | Example |
|---|---|
| Tenant ID | `11111111-…` |
| Client ID of registration B | `33333333-…` |
| Client secret of registration B | Send it through a secure channel |
| API base URL | `https://api.example.com` |
| Scope names | `api://<api-client-id>/Notes.Read`, `api://<api-client-id>/Notes.ReadWrite` |

Acme gives you one value: the redirect URI for registration B.

**CAUTION:** The API must use HTTPS at a fixed origin. Acme does not send tokens to an HTTP address.

### 5.4 Select the Application ID URI

Entra ID makes the scope names from the Application ID URI of registration A. You have two options.

| Option | Scope name example | Use it when |
|---|---|---|
| `api://<api-client-id>` | `api://2222…/Notes.Read` | Acme connects to one deployment of the API |
| The HTTPS origin of the API | `https://api.example.com/Notes.Read` | Acme connects to more than one deployment of the API |

For the second option, the domain must be a verified domain of your tenant.

The two options give the same audience in the access token: the client ID of registration A. The validation rules
in section 6 do not change.

### 5.5 The scope names in the token response

Entra ID reports the granted scopes to the client in the `scope` field of the token response. Acme reads this
field to know which operations the user can do.

The Entra ID documentation does not give the format of this field for your own API. Its examples show the full
scope name, with the Application ID URI. An example is `api://<api-client-id>/Notes.Read`.

| Application ID URI | Scope names that Acme accepts in the `scope` field |
|---|---|
| `api://<api-client-id>` | The full scope name only |
| The HTTPS origin of the API | The full scope name and the short scope name, for example `Notes.Read` |

If the `scope` field is absent, Acme uses the scopes that it requested.

**NOTE:** The `scope` field of the token response and the `scp` claim of the access token are different items.
The `scp` claim contains the short scope names. The API reads the `scp` claim only.

**CAUTION:** Do a test connection with one user before you connect all users. If the user cannot do the operations after
the connection, the format of the `scope` field is the possible cause. Tell Acme.

## 6. Token validation rules

The file `app/auth.py` validates each request. The file `app/signing_keys.py` supplies the signing keys. The API
accepts a token only if all the checks pass. The API does the checks in this sequence.

| No. | Check | Claim | Rule | Purpose |
|---|---|---|---|---|
| 1 | Algorithm | token header `alg` | Must be RS256 | Stops unsigned tokens and symmetric-key forgeries |
| 2 | Signature | token header `kid` | The signature must be correct for the signing key with that `kid` | Proves that Entra ID issued the token |
| 3 | Time | `exp`, `nbf`, `iat` | The token must be valid now. `exp` must be present. The tolerance is 60 seconds | Allows for clock differences |
| 4 | Issuer | `iss` | Must equal `https://login.microsoftonline.com/<tenant-id>/v2.0` | Accepts your tenant and v2.0 tokens only |
| 5 | Audience | `aud` | Must equal the client ID of registration A | Refuses tokens for other APIs |
| 6 | Tenant | `tid` | Must equal your tenant ID | Second check of the tenant |
| 7 | User | `oid` | Must be present | Identifies the user |
| 8 | Client | `azp` | Must be in the allow-list, if you set one | Refer to section 9 |
| 9 | Scope | `scp` | Must contain the scope that the endpoint needs | Limits each endpoint to the necessary permission |

### 6.1 Scope check

The `scp` claim is a list of scope names with a space between them.

1. Divide the value at each space.
2. Compare each full name with the necessary scope.

**CAUTION:** Do not use a substring test. `Notes.Read` is the first part of `Notes.ReadWrite`. A substring test
gives write access to a read-only token.

The scope `Notes.ReadWrite` includes the scope `Notes.Read`. Thus a token with `Notes.ReadWrite` can also read.
The table `IMPLIED_SCOPES` in `app/auth.py` contains this rule.

Each endpoint declares its necessary scope with the FastAPI `Security` function. Refer to `ReadPrincipalDep` and
`WritePrincipalDep` in `app/auth.py`.

### 6.2 Signing keys

The API gets the signing keys from this address:

`https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`

The API uses the `PyJWKClient` class of the PyJWT library for this function.

- The API keeps the signing keys in a cache for 24 hours.
- Entra ID replaces the signing keys without a notice.
- If a token has an unknown `kid`, the API gets the signing keys again.
- After a successful download, the API does not get the signing keys again for 30 seconds.
- If a download fails, the API keeps the signing keys in the cache. Tokens with a known `kid` continue to operate
  until the cache is 24 hours old.
- If the API cannot get the signing keys that a token needs, it sends status 503.

**CAUTION:** Without the 30-second limit, an attacker can send tokens with false `kid` values. Each request then
causes a download.

**CAUTION:** A download that fails does not start the 30-second limit. While Entra ID does not respond, each token
with an unknown `kid` causes one download attempt.

### 6.3 Token types

- The API accepts delegated tokens only.
- An app-only token has no `scp` claim. The API refuses it with status 403.
- The API does not validate ID tokens. ID tokens are for the client. The API receives access tokens only.

## 7. Endpoints

| Endpoint | Necessary scope | Response |
|---|---|---|
| `GET /healthz` | None | `{"status": "ok"}` |
| `GET /whoami` | `Notes.Read` | `tenant_id`, `object_id`, `scopes` and `client_id`. Also `name` and `username`. These two are `null` if the token does not contain them |
| `GET /notes` | `Notes.Read` | `notes`: the list of the notes of the user |
| `POST /notes` | `Notes.ReadWrite` | The new note: `id`, `text` and `created_at` |

**NOTE:** The scope `Notes.ReadWrite` includes the scope `Notes.Read`.

**NOTE:** `tenant_id` is the `tid` claim. `object_id` is the `oid` claim.

The body of `POST /notes` is `{"text": "..."}`. The text must have 1 to 2000 characters.

The API keeps the notes in memory. The key is (`tid`, `oid`). Thus each user sees only their own notes.

The notes endpoints have one read operation and one write operation. Each operation needs a different scope. Acme
can then give the user a read operation and a write operation with different permissions.

## 8. Error responses

### 8.1 Response table

| Condition | Status | `WWW-Authenticate` header |
|---|---|---|
| No bearer token in the `Authorization` header | 401 | `Bearer` |
| The token fails check 1, 2, 3, 4, 5, 6 or 7 | 401 | `Bearer error="invalid_token"` |
| The token is valid, but the client is not in the allow-list | 403 | None |
| The token is valid, but the scope is missing | 403 | `Bearer error="insufficient_scope", scope="…"` |
| The API cannot get the signing keys | 503 | None. The response contains `Retry-After: 5` |

### 8.2 How Acme reacts

| Status | Acme action |
|---|---|
| 401 | If the request is safe to send again, Acme refreshes the token one time and sends the request again one time. After a second 401, Acme disconnects the user. The user must connect again |
| 403 with `insufficient_scope` | Acme reports a missing permission. The connection stays |
| 403 without `insufficient_scope` | Acme reports the refusal. Acme does not refresh the token. The connection stays |
| 503 or 429 | The connection stays. For a read operation, Acme sends the request a maximum of three times. Acme waits for the time in the `Retry-After` header. Acme does not send a write request again |

Obey these rules:

- Send 401 only when a new token can correct the problem. Acme does not read the error code of a 401.
- Do not send 401 for a missing permission. Send 403.
- Write `error="insufficient_scope"` exactly, with the quotation marks.
- Do not send 401 when the API cannot get the signing keys. Send 503.
- Send a `Retry-After` header with a 503. Use a number of seconds.

**CAUTION:** A 401 for the wrong reason disconnects users. For example, a 401 during a network failure makes each
user connect again.

## 9. Client allow-list

Each access token contains the `azp` claim. The `azp` claim is the client ID of the application that requested
the token.

To accept tokens from the Acme client only:

1. Get the client ID of registration B.
2. Set `ALLOWED_CLIENT_IDS` to that client ID.

The API then refuses tokens from all other applications. The API also refuses a token that has a valid user and
valid scopes.

- The value is a setting. It is not a constant in the code. Your tenant makes the client ID when you create
  registration B.
- If the setting is empty, the API accepts all clients that Entra ID permits.

The allow-list is the second control. Entra ID is the first control:

- Entra ID issues a delegated token for the API only to an application that has the scopes of A.
- Other applications in the tenant can get an app-only token for the API. The API refuses that token because it has
  no `scp` claim.

## 10. User identity

The API uses (`tid`, `oid`) as the identity of the user.

- `oid` is the object ID of the user in the tenant.
- `oid` does not change.
- `oid` is the same in all applications of the tenant.

**CAUTION:** Do not use the email address or the username as the identity. They can change. A different person
can receive them later. Use them for display only.

Acme identifies the account by the issuer and the `oid` of the ID token. The issuer contains the tenant ID. Acme
refuses a sign-in from a different tenant. Thus the API and Acme agree on the identity of the user.

## 11. Settings

The file `.env` contains the settings. The file `.env.example` shows each setting.

### 11.1 The API

| Setting | Mandatory | Definition |
|---|---|---|
| `TENANT_ID` | Yes | Your tenant ID. Use the GUID. Do not use a domain name |
| `API_CLIENT_ID` | Yes | The client ID of registration A. Use the GUID. Do not use the Application ID URI |
| `AUTHORITY_BASE_URL` | No | The default is `https://login.microsoftonline.com`. For a local run, use the address of the mock Entra ID |
| `ALLOWED_CLIENT_IDS` | No | The permitted client IDs, with a comma between them. Each value must be a GUID |

The API does not start if a value is not valid. The error message shows the incorrect setting.

`AUTHORITY_BASE_URL` must use HTTPS. An HTTP address is permitted only for `localhost`.

**CAUTION:** `AUTHORITY_BASE_URL` controls which issuer the API accepts. Do not deploy the API with the address of
the mock Entra ID.

The API has no secret. It uses public signing keys only.

### 11.2 The demo client

| Setting | Mandatory | Definition |
|---|---|---|
| `DEMO_CLIENT_ID` | Yes | The client ID of registration B |
| `DEMO_CLIENT_SECRET` | Yes | The client secret of registration B |
| `API_BASE_URL` | No | The default is `http://localhost:8000` |
| `API_APP_ID_URI` | No | The Application ID URI of registration A. The default is `api://<API_CLIENT_ID>` |

The demo client also reads `TENANT_ID`, `API_CLIENT_ID` and `AUTHORITY_BASE_URL`.

### 11.3 The mock Entra ID

The mock Entra ID reads `TENANT_ID`, `API_CLIENT_ID`, `AUTHORITY_BASE_URL`, `DEMO_CLIENT_SECRET` and
`API_APP_ID_URI`. It uses `AUTHORITY_BASE_URL` to make the issuer of each token.

### 11.4 Local addresses

| Component | Address |
|---|---|
| The API | `http://localhost:8000` |
| The mock Entra ID | `http://localhost:4050` |
| The callback of the demo client | `http://localhost:8765/callback` |

## 12. Local development tools

### 12.1 The mock Entra ID

The file `dev/mock_entra.py` is a local replacement for Entra ID. Use it to run the full flow on one computer,
without a tenant.

The mock Entra ID has three endpoints:

- An authorize endpoint. It signs in a test user immediately. It has no login page.
- A token endpoint.
- A signing-keys endpoint. The API reads the signing keys from it.

The token endpoint does these steps:

1. It compares the client secret with `DEMO_CLIENT_SECRET`.
2. It checks the PKCE value.
3. It issues an access token.
4. It issues an ID token, if the request contains the scope `openid`.
5. It issues a refresh token, if the request contains the scope `offline_access`.
6. It reports the granted scopes in the `scope` field of the response, with the full scope names.

The mock Entra ID refuses a scope that does not start with the Application ID URI of this API. It does not check
the scope name.

The mock Entra ID uses the same URL paths and the same claims as Entra ID. Thus the API code is the same in the
two modes. Only `AUTHORITY_BASE_URL` is different.

**CAUTION:** Do not deploy the mock Entra ID. It is for development and demos only.

**NOTE:** The mock Entra ID makes a new signing key at each start. After you start it again, the API can send 401
for 30 seconds. Then the API gets the new signing key.

### 12.2 The demo client

The file `scripts/demo_client.py` does the work of Acme. Use it to show the flow before Acme connects.
It uses the Authlib library for the OAuth2 flow.

The demo client does these steps:

1. It makes the authorize URL with a PKCE value, a state value and a nonce value.
2. It opens the browser.
3. It receives the code at `http://localhost:8765/callback`.
4. It checks the state value.
5. It exchanges the code, the PKCE verifier and the client secret for tokens.
6. It validates the ID token and the nonce value.
7. It shows the identity of the user.
8. It calls `/whoami`.
9. It creates a note.
10. It lists the notes.
11. It calls `/whoami` with no token.
12. It refreshes the token.
13. It calls `/whoami` again.

The demo client operates with the mock Entra ID and with a real tenant.

## 13. Repository layout

```
 sample-auth-app/
 ├── README.md              what the sample is and how to run it
 ├── pyproject.toml         dependencies and tool settings
 ├── uv.lock                the exact versions of the dependencies
 ├── .env.example           example settings (the defaults use the mock Entra ID)
 ├── .gitignore             files that you must not commit
 ├── app/
 │   ├── main.py            makes the FastAPI application
 │   ├── config.py          reads and validates the settings
 │   ├── auth.py            validates tokens and checks scopes
 │   ├── signing_keys.py    gets the signing keys with PyJWKClient
 │   ├── schemas.py         the request and response models
 │   ├── note_store.py      keeps the notes in memory
 │   └── routers/           health.py, whoami.py, notes.py
 ├── scripts/
 │   └── demo_client.py     does the work of Acme
 ├── dev/
 │   └── mock_entra.py      local replacement for Entra ID
 ├── tests/                 automated tests
 └── docs/
     ├── app-authorization.md   this document
     └── acme-oauth2.md         how Acme uses OAuth2
```

## 14. Fault isolation

| Symptom | Possible cause | Correction |
|---|---|---|
| The API does not start | A setting is not valid. For example, `TENANT_ID` is a domain name | Read the error message. Correct the setting in `.env` |
| The API sends 401 for each token | Entra ID issues v1.0 tokens | Do step 10 of section 5.1 |
| The API sends 401 for each token | `API_CLIENT_ID` is the client ID of registration B | Use the client ID of registration A |
| The API sends 401 for each token, with the mock Entra ID | You started the mock Entra ID again. It has a new signing key | Wait 30 seconds. Then try again |
| The API sends 403 with `insufficient_scope` | The token does not contain the necessary scope | Add the permission to registration B. Then connect again |
| The API sends 403 with no `WWW-Authenticate` header | The client is not in the allow-list | Add the client ID to `ALLOWED_CLIENT_IDS` |
| The API sends 503 | The API cannot get the signing keys from Entra ID. Or `TENANT_ID` is not the ID of your tenant | Do a check of the network, `AUTHORITY_BASE_URL` and `TENANT_ID` |
| The API sends 422 for a request with no token | The request body is not valid JSON. FastAPI reads the JSON text before it checks the token | Correct the request body |
| Entra ID shows error `AADSTS65001` at sign-in | Consent is missing | Do step 11 of section 5.2 |
| Entra ID shows error `AADSTS50011` at sign-in | The redirect URI is not in registration B | Add the redirect URI that Acme gave you |

## 15. Limits of the sample

The sample does not include these functions:

- **Permanent storage.** The notes stay in memory. A restart erases them.
- **Authorization by role or by owner.** A production API also checks the role of the user or the owner of the data.
- **More than one tenant.** For many tenants, replace the single issuer check with a list of permitted tenants.
- **Rate limits, logs and CORS.** Add them with the tools that your company uses.
- **Token revocation.** Refer to section 15.1.

### 15.1 Token revocation

Entra ID has no endpoint to revoke a token.

- An access token stays valid until it expires. The default lifetime is 60 to 90 minutes.
- A refresh token stays valid until your company revokes the sessions of the user or the grant.
- A session revocation stops new tokens only. A permission removal from registration B also stops new tokens only.

**CAUTION:** To stop access immediately, the API must refuse the user or the client. For example, check a
deny-list on each request.

## 16. Libraries

### 16.1 Libraries in the sample

| Library | Where | Function |
|---|---|---|
| FastAPI | `app/`, `dev/` | The web framework, the dependency system and the scope declarations |
| PyJWT | `app/`, `dev/`, `scripts/` | Checks the signature and the claims of a token. Its `PyJWKClient` class gets the signing keys |
| pydantic-settings | `app/`, `dev/`, `scripts/` | Reads and validates the settings |
| Authlib | `scripts/`, `dev/` | Does the authorization code flow with PKCE, and the token refresh |
| httpx2 | `scripts/`, `tests/` | Sends the HTTP requests of the demo client and of the tests |
| pytest | `tests/` | Runs the automated tests |
| Ruff | Development | Formats and examines the code |

The API in `app/` needs FastAPI, PyJWT and pydantic-settings only.

**NOTE:** Use PyJWT 2.14 or later. From that version, `PyJWKClient` limits the downloads for unknown `kid` values.

### 16.2 Alternative libraries

| Library | Function | When to use it |
|---|---|---|
| MSAL for Python (`msal`) | The official library for a client that gets tokens from Entra ID | In a client application. It does the same work as Authlib in the demo client |
| `fastapi-azure-auth` | A community library that validates Entra ID tokens in FastAPI | In an API, as a replacement for `app/auth.py` |

**CAUTION:** MSAL gets tokens. It does not validate access tokens for an API. Do not use it for the checks in
section 6.

**CAUTION:** If you replace `app/auth.py` with a library, make sure that the status codes agree with section 8.
Run the tests in `tests/` to make sure.
