# Refresh-token `ExpiresAt` storage upgrade

Section 4 changes the EF Core storage mapping for
`BehrouzanRefreshTokens.ExpiresAt`. The previous mapping used each database
provider's default `DateTimeOffset` representation. The new mapping stores the
UTC instant as a signed 64-bit .NET tick count (100-nanosecond intervals since
`0001-01-01T00:00:00Z`). This makes expiration comparison translatable inside
the conditional database update used for atomic refresh-token rotation.

## Sample.Api

`Sample.Api` uses the persisted SQLite connection
`Data Source=sample-auth.db`, has no EF migrations, and initializes its schema
with `Database.EnsureCreatedAsync()`. For disposable development data, stop the
sample, delete the database in the process working directory, and restart it.
When running from the sample project directory, the exact PowerShell steps are:

```powershell
Push-Location samples/Sample.Api
Remove-Item -LiteralPath sample-auth.db -ErrorAction SilentlyContinue
dotnet run
Pop-Location
```

If the sample is launched with a different working directory, delete the
`sample-auth.db` file in that directory instead. Deletion discards all sample
users and authentication data. If that data must be retained, use the
data-converting migration described below rather than recreating the database.

## Existing package-consumer databases

Consumers with existing refresh-token rows must create a provider-specific,
data-converting migration. A column type change alone is unsafe: it can cause
the provider to reinterpret the old `DateTimeOffset` representation as if it
were already a .NET tick value.

The migration must:

1. Add a temporary signed 64-bit integer column.
2. Read each existing `ExpiresAt` using the provider's previous
   `DateTimeOffset` representation.
3. Normalize that value to UTC and convert it to .NET UTC ticks.
4. Store the converted tick value in the temporary column.
5. Verify that every non-null source value was converted and that the instants
   are unchanged.
6. Replace the old column with the converted column, preserving its required
   constraint and name.

The exact conversion SQL differs across SQL Server, PostgreSQL, SQLite, and
other providers. Generate and review the migration for the application's
actual provider and previous column type. Do not deploy an automatically
generated `AlterColumn` migration without an explicit data conversion and
verification step.

## Logout from all devices

`IRefreshTokenManager<TKey>.RevokeAllAsync` revokes the active, unexpired
refresh tokens belonging to one user. Callers must obtain `userId` from the
currently authenticated identity; it must not be accepted from untrusted
request input. The operation does not shorten already-issued access-token
lifetimes, and security-stamp changes do not invoke it automatically. A login
that completes after bulk revocation may create a fresh session.

The EF implementation performs one conditional database update. On SQLite, a
rotation that has committed before bulk revocation is included in the bulk
update, while a rotation started after bulk revocation has completed cannot
replace the revoked token. SQLite permits only one writer at a time, so truly
overlapping writes may instead surface `SQLITE_BUSY` depending on connection
timeout and transaction timing. The tests prove both completed-operation
orderings on SQLite; they do not prove behavior for overlapping transactions.
Other providers follow their configured transaction isolation and locking
behavior, which this test suite does not verify. A stronger cross-provider
ordering guarantee would require an explicit provider-specific locking policy
or additional per-user revocation state.
