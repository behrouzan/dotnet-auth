# Authentication flows

The library supplies managers; routing, request/response contracts, status codes, antiforgery, and bearer validation are application responsibilities. [Sample.Api](../samples/Sample.Api/Endpoints/AuthEndpoints.cs) is the reference endpoint implementation.

## Cookie and bearer are separate

Cookie sign-in uses ASP.NET Core Identity's application scheme and is appropriate for browser sessions. Its sample login/logout endpoints validate an antiforgery request token. Bearer sign-in validates a signed JWT on each request and is used by the token logout endpoints. A cookie does not authenticate a bearer-only endpoint, and a bearer token does not authenticate an endpoint requiring `IdentityConstants.ApplicationScheme`.

## Token login

Call `TokenLoginManager<TUser, TKey>.LoginAsync(identifier, password)`. On success it produces an access JWT and a raw refresh token. The access JWT contains the canonical Identity user ID as `sub`, plus `iat` and `jti`; the refresh token is opaque and its hash is persisted.

Expected unsuccessful results are `InvalidCredentials`, `LockedOut`, `NotAllowed`, `RequiresTwoFactor`, and `RefreshTokenCreationFailed`. The sample returns 401 for the credential/status failures, 403 for `RequiresTwoFactor`, and 503 if refresh-token creation fails. `RequiresTwoFactor` means the password was accepted but the library does not complete a second factor or issue tokens.

## Refresh

Call `TokenRefreshManager<TUser, TKey>.RefreshAsync(refreshToken)`. A successful refresh atomically rotates the refresh token and returns a new access/refresh pair. Replace the client-held refresh token immediately; using a rotated token again is reported as `ReuseDetected`.

Possible refresh outcomes include `InvalidToken`, `Expired`, `Revoked`, `ReuseDetected`, `ConcurrencyConflict`, `LockedOut`, `NotAllowed`, and `RequiresTwoFactor`. The sample maps the current-account states and 2FA to 403, `ConcurrencyConflict` to 409, and other failures to 401. Refresh does not complete 2FA; the user must follow the application's sign-in/2FA process.

## Logout one session

`IRefreshTokenManager<TKey>.RevokeAsync(refreshToken)` revokes one active refresh token. The sample requires a valid bearer access token, validates the supplied refresh token, and checks that its owner matches the bearer user before revocation. Do not expose a raw revoke endpoint that lets one authenticated user revoke another user's session.

## Logout all sessions

`IRefreshTokenManager<TKey>.RevokeAllAsync(userId)` revokes active, unexpired refresh tokens for one user. Derive `userId` from the authenticated identity, as Sample.Api does for its bearer `sub`; never accept it from untrusted request data. A concurrent or later login can create a new session. See [security and data considerations](security-and-data.md) for the precise concurrency boundary.

Neither logout operation immediately invalidates already-issued JWT access tokens. Keep access-token lifetimes short and enforce other application policy where immediate access revocation is required.
