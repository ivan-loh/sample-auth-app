# How Acme uses OAuth2

## 1. Purpose

This document tells you how Acme calls an external service for a signed-in user. This document calls that
external service the **vendor**. If you protect an API for Acme, you are the vendor.

This document gives the process and the rules. It does not give the implementation.

Read [app-authorization.md](app-authorization.md) to learn how to protect your API for Acme.

### 1.1 Conventions

- "Must" shows a mandatory rule.
- "Can" shows an option.
- **CAUTION** shows a risk to security or to data.
- **NOTE** gives more information.

### 1.2 Key facts

- Acme uses the OAuth2 authorization code flow with PKCE. Acme is a confidential client.
- Each user connects their vendor account one time. Then Acme calls the vendor with the permissions of that user.
- OAuth2 gives permission to call an API. It does not identify the account. Acme identifies the account in a
  separate step.
- Acme keeps all tokens. The integration code does not receive a token.
- The sign-in to Acme and the connection to a vendor are two different operations.

## 2. Terms

| Term | Definition |
|---|---|
| User | A person who is signed in to Acme |
| Customer | The company that the user works for |
| Integration | The part of Acme that connects to one vendor |
| Vendor | The external service that has the API |
| App registration | The OAuth client that the customer creates at the vendor. It has a client ID and a client secret |
| Connection | The stored grant of one user for one integration |
| Access token | A token that Acme sends with each API request. It expires after a short time |
| Refresh token | A token that Acme uses to get a new access token |
| Scope | A named permission in a token |
| State | A value that Acme sends to the vendor and that the vendor sends back |
| PKCE | A control that stops the use of a stolen code. It uses a secret verifier and a public challenge |

## 3. Data that Acme keeps

```
 CUSTOMER (one time)                          USER (one time for each user)
 ───────────────────                          ─────────────────────────────
 creates an app registration at the vendor    selects Connect and signs in
 and saves its values in Acme                  at the vendor
            │                                            │
            ▼                                            ▼
 ┌─────────────────────────┐              ┌──────────────────────────────┐
 │ Customer settings       │              │ User connection              │
 │  tenant / client ID     │◄─────────────│  the user, the customer      │
 │  client secret          │  related to  │  the verified vendor account │
 │  (encrypted)            │              │  access token   (encrypted)  │
 └─────────────────────────┘              │  refresh token  (encrypted)  │
                                          │  granted scopes, status      │
                                          └──────────────────────────────┘
```

Each integration declares these items:

- The endpoints of the vendor.
- The necessary scopes.
- The method to identify the account.
- The API addresses that can receive the token.

The customer uses its own app registration. For a vendor with tenants, Acme uses the tenant of the customer only.
An account from a different tenant cannot connect.

## 4. Procedure: connect

Each user does this procedure one time for each integration.

```
 Browser               Acme                                  Vendor
    │                    │                                      │
    │ Connect            │                                      │
    ├───────────────────►│ • read the client ID                 │
    │                    │ • make a PKCE verifier + challenge   │
    │                    │ • make an encrypted state            │
    │ redirect to vendor │                                      │
    │◄───────────────────┤                                      │
    │                                                           │
    ├──────────────────────────────────────────────────────────►│
    │   client ID, scopes, state, PKCE challenge, redirect URI  │
    │                     the user signs in and consents        │
    │◄──────────────────────────────────────────────────────────┤
    │   redirect to Acme with a one-time code + the state       │
    │                    │                                      │
    ├───────────────────►│ 1. decrypt and check the state       │
    │                    │ 2. check the permission of the user  │
    │                    │ 3. exchange the code ───────────────►│
    │                    │    code + verifier + client secret   │
    │                    │◄──────────────────────────────────── │
    │                    │    access token, refresh token,      │
    │                    │    proof of identity, granted scopes │
    │                    │ 4. verify the account                │
    │                    │ 5. encrypt and store the connection  │
    │ back to Settings   │                                      │
    │◄───────────────────┤                                      │
```

### 4.1 Start of the connection

1. The user selects Connect.
2. Acme reads the client ID of the customer.
3. Acme makes a PKCE verifier and a PKCE challenge.
4. Acme makes an encrypted state.
5. Acme sends the browser to the vendor.
6. The user signs in at the vendor and gives consent.
7. The vendor sends the browser back to Acme with a one-time code and the state.

The state contains the user, the customer, the integration and the verifier. The state is valid for ten minutes.

### 4.2 Completion of the connection

1. Acme decrypts the state.
2. Acme makes sure that the state names the user who is signed in to this browser tab.
3. Acme checks again that the user has permission to connect this integration.
4. Acme sends the code, the verifier and the client secret to the vendor.
5. The vendor sends the access token, the refresh token, the proof of identity and the granted scopes.
6. Acme verifies the account. Refer to section 5.
7. Acme encrypts the tokens and stores the connection.
8. Acme sends the browser back to the settings page.

### 4.3 Security controls

| Control | Risk that it prevents |
|---|---|
| The state names the signed-in user | An attacker starts a flow, and the session of a different user completes it |
| Acme encrypts the state | A person reads the PKCE verifier in a URL or in a log |
| PKCE | A person uses a stolen one-time code |
| Acme sends the client secret from server to server only | The browser receives the client secret |
| Acme checks the permission again at the callback | Acme stores a grant for a user who lost access during consent |
| The state is valid for ten minutes | A person completes an old flow later |

## 5. Account verification

A token does not show which account it is for. Acme verifies the account with one of two methods. Each
integration declares its method.

### 5.1 Method 1: OpenID Connect

1. The vendor sends an ID token with the grant.
2. Acme checks the issuer, the tenant, the audience, the expiry time and the subject.
3. If the customer has a list of approved domains, Acme checks the domain of the account.

### 5.2 Method 2: profile endpoint

A vendor that does not issue an ID token uses this method.

1. Acme calls the "who am I" endpoint of the vendor with the new access token.
2. Acme reads the stable account ID from the response.

### 5.3 Rules for the account identity

- Acme identifies the account by a stable identifier from the vendor.
- For Entra ID, the stable identifier is the tenant ID and the `oid` claim of the ID token.
- Acme does not identify the account by an email address. A different person can receive an email address later.
- Acme keeps the email address or the username as a label for display only.

### 5.4 If the verification fails

If the verification fails, Acme stores nothing.

### 5.5 If the user connects a different account

1. Acme stores the new grant.
2. Acme tries to revoke the old grant at the vendor.

**NOTE:** Step 2 is possible only if the vendor has a revocation endpoint. Entra ID does not have one. A failed
revocation does not stop the connection.

## 6. Token storage

- Acme encrypts each token before it stores the token.
- Acme binds each encrypted token to the user, the customer and the integration.
- If a token moves to the record of a different user, the decryption fails. The token cannot operate with the
  incorrect identity.
- If the encryption key is missing, the storage fails. Acme does not store a token as plain text.

## 7. Procedure: API request

Each request from Acme to a vendor uses the same path.

```
 Acme has a request to send for user U
              │
              ▼
      Is the integration enabled for the customer?
      Does U have permission?  Is this operation permitted?
      Does the grant contain the necessary scopes?
              │
              ▼
      The integration code asks Acme to send the request
      (the integration code does not receive the token)
              │
              ▼
      Acme gets the credential of U
      ┌───────────────────────────────────────────────────────┐
      │ no connection ───────────► "connect your account"     │
      │ the connected account changed ──► refuse              │
      │ the token expires soon ──► refresh at the vendor      │
      │     ├─ success: store the new tokens                  │
      │     ├─ the vendor refuses: "connect again"            │
      │     └─ no response from the vendor: "try again later" │
      │ in all other conditions ──► decrypt the access token  │
      └───────────────────────────────────────────────────────┘
              │
              ▼
      Is the request for an address that the integration declared?
       ├─ yes ──► send the request with the token ──► Vendor API
       └─ no  ──► send the request without the token
```

### 7.1 Rules for each request

| No. | Rule | Detail |
|---|---|---|
| 1 | Acme keeps the tokens | The integration code receives a request function. It does not receive a credential |
| 2 | Tokens go to declared addresses only | An address is the scheme, the host and the port. Refer to section 7.2 |
| 3 | Acme gets the credential for each request | A long sequence of requests thus uses a refreshed token. A change of account stops the subsequent request |
| 4 | A vendor failure is not a disconnection | "No response from the vendor" and "not connected" are different results |
| 5 | A refused token gets one more attempt | Refer to section 7.3 |
| 6 | One refresh at a time | Parallel requests cannot replace the new tokens of each other |

### 7.2 Declared addresses

Acme sends the token to these addresses only:

- The API addresses that the integration declared.
- For an integration with a configurable API address, the API address that the customer saved.

Each declared address must use HTTPS. Acme does not send a token to an HTTP address.

Acme sends a request to all other addresses without the token. This rule includes a redirect to a different
address.

### 7.3 If the vendor sends status 401

1. Acme makes sure that the request is safe to send again.
2. Acme refreshes the token one time.
3. Acme sends the request again one time.
4. If the vendor sends 401 again, Acme disconnects the user. The user must connect again.

If the request is not safe to send again, Acme reports the 401. Acme does not refresh the token.
A request with a JSON body is safe to send again.

Acme does not read the error code of a 401.

**NOTE:** An integration can declare a validity check for the token. If the check shows that the token is good,
Acme reports a permission refusal. If the check cannot complete, the result is "try again later".

### 7.4 If the vendor sends status 403, 429 or 503

| Status | Acme action |
|---|---|
| 403 with `error="insufficient_scope"` | Acme reports a missing permission. The connection stays |
| 403 without that error | Acme reports the refusal. Acme does not refresh the token. The connection stays |
| 503 or 429 | The connection stays. For a read operation, Acme sends the request a maximum of three times. Acme waits for the time in the `Retry-After` header. Acme does not send a write request again |

### 7.5 Granted scopes

The vendor reports the granted scopes in the `scope` field of the token response. Acme compares these scope names
with the scope names that the integration declared. Acme ignores the letter case.

- If the `scope` field is absent, Acme uses the scopes that it requested.
- If the `scope` field contains no declared scope name, the user cannot do the operations that need a scope.
- An operation that needs a scope is available only if the grant contains that scope.

## 8. Procedure: disconnect

1. Acme marks the connection as disconnected. Subsequent requests do not get a token.
2. Acme tries to revoke the grant at the vendor, if the vendor has a revocation endpoint.
3. Acme deletes the stored tokens.

- A failed revocation does not stop the procedure.
- Acme keeps the record of the connected account.
- A user can disconnect only while that user has the integration.
- The customer can remove the integration. Acme then does the disconnect procedure for each user.

## 9. Changes to the customer settings

The effect of a change is different for each type of integration.

| Type of integration | Change | Effect |
|---|---|---|
| The API address is a customer setting | The tenant, the client ID or the target resource | Acme disconnects all users and deletes their tokens. The users must connect again |
| All other integrations | A setting | The connections do not change. They operate until the vendor refuses a token refresh |
| An integration with approved domains | The customer removes a domain | Acme disconnects the users who connected with an account from that domain |

## 10. Acme sign-in and vendor connection

These are two different operations.

| | Acme sign-in | Vendor connection |
|---|---|---|
| Purpose | Identifies the user to Acme | Lets Acme operate for the user at a vendor |
| Frequency | Each session | One time for each integration |
| Identity provider | The identity provider of Acme | The vendor |

Acme links the user to the vendor account that the user connected. Acme does not calculate one identity from the
other.

## 11. Standards and additions

### 11.1 Standards that Acme uses

- The authorization code flow (RFC 6749) with PKCE (RFC 7636).
- Bearer tokens (RFC 6750) and refresh tokens.
- OpenID Connect ID tokens for the identity of the account.
- The `state` parameter, which links the callback to the user who started the flow.

### 11.2 Additions by Acme

- An encrypted state that contains the PKCE verifier.
- A verified account identity as a condition to store a grant.
- Encrypted tokens that Acme binds to the user, the customer and the integration.
- Token storage by Acme only, and delivery to declared addresses only.
- Checks of the customer, the user, the operation and the scope before each request.
- Removal of grants that Acme refused or replaced, if the vendor has a revocation endpoint.
