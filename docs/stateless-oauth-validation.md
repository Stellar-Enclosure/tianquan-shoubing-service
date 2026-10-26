# Stateless OAuth validation record

Validated on 2026-10-25 with JDK 25 and the task Maven settings. This record covers the IdP Admin/Core implementation of S02–S05. Starter/GatewayAdapter S06 has separate owner evidence.

## Completed commands

| Command | Result | Local log |
| --- | --- | --- |
| `./mvnw -B -ntp -s /tmp/stellar-pac-20261023-implementation/maven-settings.xml -pl :stellar-enclosure-tianquan-shoubing-admin test` | 466 tests, 0 failures, 0 errors, 0 skipped | `/tmp/stellar-pac-20261023-implementation/idp-admin-all-unit-3.log` |
| `./mvnw -B -ntp -s /tmp/stellar-pac-20261023-implementation/maven-settings.xml -pl :stellar-enclosure-tianquan-shoubing-core test` | 29 tests, 0 failures, 0 errors, 0 skipped | `/tmp/stellar-pac-20261023-implementation/idp-core-all-unit.log` |
| `git diff --check` | Passed | No output |
| Diff of tracked SQL migrations | No tracked migration modifications, removals, or renames | No output |

The one new IdP migration remains `V20261023_001__stateless_oauth_state.sql` with frozen SHA-256 `21134dca1334ff8af42ac455fd3b2b584f06c29f92846a7bf565a1625115ea13`. The managed manifest retains the preceding scripts and their hashes.

## Relevant coverage

- `OAuthConsentRoundTripTest`: 30 tests through the real Spring Security/SAS filters, native converters/providers, signed JWTs, encrypted persistence converters, and transactional fixture. Covers login, Consent selection/cancellation, Code/PKCE, ID Token, Access Token, UserInfo, Refresh, browser binding, replay closure, failures, mandatory password change, and current SSO logout. The fixture substitutes SQL repositories and a transaction manager; it is not a PostgreSQL acceptance test.
- Authentication and interaction tests: 8 authentication JWT purpose/state/expiry tests and 8 interaction binding tests. Access/ID/CSRF JWTs cannot become SSO credentials; browser/CSRF/issuer/resource mismatches and expired/consumed interactions are rejected.
- SSO tests: 4 scope tests verify that closing one authentication affects its linked grants without using a global subject or browser-wide revocation query.
- Existing native protocol, tenant isolation, client management, migration/schema/mapper contracts, revocation, Outbox, resource authority, retention, constructor qualification, and security metrics tests also pass in the full Admin run.

Successful Consent and Code exchange explicitly assert that no HttpSession is created. ID Token output does not contain `sid`. The SAS authorization endpoint's internal session-authentication strategy is explicitly disabled in addition to the stateless SecurityContext/CSRF configuration. The retired `/connect/logout` endpoint returns 410; discovery exposes the tenant's SQL-backed `egon_sso_logout_endpoint` instead of a session logout endpoint.

## Implementation boundaries

The implementation reuses SAS through its RequestCache, CSRF, authentication filter, and Provider extension points. PostgreSQL interaction/authentication facts replace session state. The existing transactional Provider decorator couples credential consumption, signing/persistence, audit, and Outbox work. A refresh replay commits family closure before returning `invalid_grant`.

The local identity authority adapter resolves directly through the IdP's database owner and cannot call its own HTTP authority endpoints recursively. Audit receipt creation uses independent committed transactions; an outer read-only or business transaction cannot turn an uncommitted receipt into authorization success.

Retention follows the project's logical deletion convention. Stored `retain_until` values govern deletion, and SQL reference checks protect authentication/interaction facts still used by live grants. The unused Redis refresh implementation was removed after confirming that the production Bean uses `SubjectRevocationRefreshTokenStoreAdapter`. Existing local runtime data and spool files were not removed.

## Remaining runtime acceptance

No application, real database, container, or browser was started. Live PostgreSQL migration execution, locks/concurrent consumers, cross-node and restart behavior, reverse proxy Cookie behavior, and browser SSO remain unverified. The PostgreSQL integration profile is available for the user's configured environment.

Host deployment still requires the finite issuer tuples and final RBAC SQL/HTTP runtime configuration described in [the configuration handoff](stateless-oauth-host-handoff.md). The shared Components Outbox logical-to-physical schema routing must also be checked during host integration. Compilation and the fixture transaction tests do not establish production Outbox atomicity.

No commit or push was created.
