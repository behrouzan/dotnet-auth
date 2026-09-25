# Sample.Api

The sample exposes the existing cookie flow alongside a separate JWT bearer flow.
It is the executable reference for the repository's current API; start with the
[root overview](../../README.md), [getting started](../../docs/getting-started.md),
[authentication flows](../../docs/authentication-flows.md), and
[security/data guidance](../../docs/security-and-data.md) for rationale and
integration details.
It uses SQLite and `EnsureCreatedAsync`; delete `sample-auth.db` when model changes
require a fresh development database.

## Local configuration

Set a Base64-encoded signing key containing at least 32 random bytes. Do not put
the key in `appsettings*.json` or commit it. For example, using .NET user secrets:

```powershell
dotnet user-secrets init --project samples/Sample.Api
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$key = [Convert]::ToBase64String($bytes)
dotnet user-secrets set "TokenAuthentication:SigningKey" $key --project samples/Sample.Api
```

Alternatively set the `TokenAuthentication__SigningKey` environment variable.
Issuer, audience, HS256 algorithm, and access/refresh lifetimes are non-secret
settings in `appsettings.json`. Startup fails when any required token setting is
missing or invalid.

The development seeder creates `behzad` with password `Test123!` on a fresh
database. This credential is for local sample use only.

## HTTP API

- `POST /auth/token/login` with `{ "identifier": "...", "password": "..." }`
- `POST /auth/token/refresh` with `{ "refreshToken": "..." }`
- `POST /auth/token/logout` with a bearer access token and the session's
  `{ "refreshToken": "..." }`
- `POST /auth/token/logout-all` with a bearer access token and no body

Successful login and refresh return `accessToken`, `accessTokenExpiresAt`, and
`refreshToken`. Token logout endpoints accept bearer authentication only. Logout
of one session verifies that the refresh token belongs to the authenticated user;
logout-all derives the user ID from the validated bearer subject and current user.

Two-factor completion is intentionally outside this sample. When Identity
requires 2FA, token login or refresh returns HTTP 403 and no tokens. Logout-all
revokes active refresh tokens but does not immediately expire already-issued
access tokens. See the linked guides for flow details and security boundaries.
