# Keycloak Account Events SPI

A Keycloak SPI extension that lets a user retrieve their own authentication
event history (login, logout, login error, ...) from the account console or any
first-party application, using the user's own access token. No admin
credentials involved.

![CI](https://github.com/AdrianIAna/keycloak-account-events/actions/workflows/ci.yml/badge.svg)
![Keycloak](https://img.shields.io/badge/Keycloak-26.x-blue)
![License](https://img.shields.io/github/license/AdrianIAna/keycloak-account-events)

## Why

Keycloak records authentication events, but the only built-in way to read them
is the Admin Events API, which needs an administrative token with the
`view-events` role. That doesn't work for self-service "recent login activity"
screens, where an application should show users their own history with their
own token and nothing more.

Keycloak's account console shows active sessions ("Device Activity") but has no
login-history endpoint. This extension adds one, scoped strictly to the caller.

## How It Works

The extension registers a `RealmResourceProvider` that serves:

```
GET /realms/{realm}/account-events/me
```

Each request goes through the same gatekeeping as Keycloak's built-in account
API:

1. The `Authorization: Bearer` token is validated (signature, issuer, expiry);
   missing or invalid tokens get a `401`.
2. Lightweight access tokens (which omit `aud`/`resource_access` from the wire
   token) have their claims recovered through Keycloak's introspection
   transform, the same mechanism the built-in account API uses.
3. The token must target the `account` client, else `401`.
4. CORS origins are enforced against the client's configured Web Origins for
   browser callers; a preflight `OPTIONS` handler is included.
5. Service-account tokens (`client_credentials`) are rejected with `401`.
6. The token must carry the `account` client's `view-profile` or
   `manage-account` role, else `403`.
7. The realm event store is queried, hard-scoped to the token's own subject.

There is no user-id request parameter anywhere: results are bound to the
authenticated subject, so a caller can only ever read their own events.

### Query parameters

| Parameter   | Description                                                | Default |
|-------------|------------------------------------------------------------|---------|
| `type`      | Event type filter; repeatable (e.g. `type=LOGIN&type=LOGOUT`) | all types |
| `client`    | Client-id filter                                           | all clients |
| `dateFrom`  | Start date (`yyyy-MM-dd` or epoch millis)                  | unbounded |
| `dateTo`    | End date (`yyyy-MM-dd` or epoch millis)                    | unbounded |
| `ipAddress` | IP-address filter                                          | all |
| `first`     | Pagination offset (clamped to `>= 0`)                      | `0` |
| `max`       | Maximum results (clamped to the configured cap, default 1000) | `100` |

Response: a JSON array of Keycloak `EventRepresentation` objects (`type`, `time`,
`ipAddress`, `clientId`, `details`, ...). Any custom fields written into an event's
`details` map by other SPIs (for example GeoIP/User-Agent enrichment) are passed
through unchanged. To page through more events than the cap, repeat the request
with increasing `first` until a short page is returned.

### Responses

| Status | Meaning |
|--------|---------|
| `200`  | Array of the caller's own events |
| `400`  | Invalid `type` / `dateFrom` / `dateTo` value |
| `401`  | Missing/invalid bearer token, wrong audience, or a service-account token |
| `403`  | Token lacks the account `view-profile`/`manage-account` role, or disallowed CORS origin |
| `404`  | The realm's `account` client is missing or disabled (mirrors the built-in account API) |

> Note: per the Jakarta REST spec, a non-numeric value for the `int` parameters
> `first`/`max` (e.g. `?max=abc`) is rejected by parameter conversion as `404`,
> not `400`.

## Compatibility

| Extension Version | Keycloak Version |
|-------------------|------------------|
| 0.1.x             | 26.6 – 26.7 (built against 26.7.0) |

The floor is 26.6: the extension uses the `AuthResult` record accessors
(added in 26.5) and the `Cors.checkAllowedOrigins` API (added in 26.6). It may
work with newer versions, but no promises, since it builds on internal server
SPIs. CI compiles and tests against every supported version.

> Note: this provider implements the internal `realm-restapi-extension` SPI, so
> Keycloak logs a `KC-SERVICES0047` warning at build time. That is expected.

## Installation

1. Download the JAR from the [releases page](../../releases) (or build it from
   source, below) and copy it to `/opt/keycloak/providers/`
2. Run `bin/kc.sh build` (providers are registered at build time)

```bash
cp keycloak-account-events-*.jar /opt/keycloak/providers/
bin/kc.sh build
```

3. Enable event storage for the realm. Keycloak does not persist user events by
   default, so without this step the endpoint always returns `[]`. In the admin
   console: *Realm settings → Sessions → User events → Save events = On* (make
   sure the saved types include at least `LOGIN`, `LOGOUT`, `LOGIN_ERROR`), or
   via the admin CLI:

```bash
kcadm.sh update events/config -r <realm> -s eventsEnabled=true
```

The endpoint is then available at `/realms/{realm}/account-events/me`. It works
even when the account console feature is disabled (`--features-disabled=account`),
because it relies on the `account` client's roles being present in the token, not
on the account console itself.

### Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--spi-realm-restapi-extension--account-events--max-results` | `1000` | Upper bound on events per response (`max` is clamped to this); must be a positive integer, the server refuses to start otherwise |
| `--spi-realm-restapi-extension--account-events--enabled` | `true` | Standard Keycloak provider switch; set `false` to disable the endpoint entirely |

## Building from Source

Requires Java 17+ and Maven 3.8+.

```bash
mvn clean package
```

Output: `target/keycloak-account-events-<version>.jar`. All Keycloak dependencies
are `provided` (supplied by the server at runtime), so the JAR is small.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.
For security problems, follow the [security policy](SECURITY.md) instead of opening
a public issue.

## License

[Apache License 2.0](LICENSE)
