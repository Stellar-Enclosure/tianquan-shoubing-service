# tianquan-shoubing-service

Identity, OAuth2/OIDC authorization-server and resource-token infrastructure for Stellar Enclosure's Tianquan platform. All first-party modules start at **0.0.1**.

## Current capabilities

- Manage identity users, password reset and user-wide token revocation; manage tenants and memberships, and provide tenant-aware login/profile/bootstrap behavior.
- Configure OAuth clients, redirect URIs, client secrets and permitted resource URIs; implement authorization-code, refresh-token and client-credentials processing through Spring Authorization Server.
- Expose OAuth/OIDC metadata, consent, token/revocation and JWK support; manage signing-key publication, activation and retirement.
- Manage resource servers and client-resource grants; issue resource-bound USER/SERVICE tokens and validate the associated audience/version/scope constraints.
- Expose identity audit APIs and reusable service-side token validation/client support for platform applications and gateways.

## Modules and integration

| Module | Responsibility |
|---|---|
| [Core](stellar-enclosure-tianquan-shoubing-core/) | Identity/token/resource contracts, verification and shared security primitives. |
| [RPC contract](stellar-enclosure-tianquan-shoubing-rpc-contract/) | Cross-process Protobuf/gRPC identity contracts. |
| [Starter](stellar-enclosure-tianquan-shoubing-starter/) | Spring integration for resource-bound bearer validation and service-client support. |
| [Gateway adapter](stellar-enclosure-tianquan-shoubing-gateway-adapter/) | Shoubing identity/resource validation in the Yuheng gateway pipeline. |
| [Admin](stellar-enclosure-tianquan-shoubing-admin/) | Executable identity administration and OAuth/OIDC authorization server with persistence and key management. |

Management APIs use `/api/v1/tianquan-shoubing`; [tianquan-shoubing-web](https://github.com/Stellar-Enclosure/tianquan-shoubing-web) provides the console. Yuheng Edge is the browser OAuth client/BFF and retains tokens on the server. Tianshu and downstream services consume SERVICE tokens for their own resource/scope checks.

At the code level, Shoubing handles identity and token issuance; [Jianshen](https://github.com/Stellar-Enclosure/tianquan-jianshen-service) owns role graphs, active roles and fine-grained USER authorization. OAuth resource grants here do not replace Jianshen's function/data/field decisions. A package build does not establish a working browser login, consent, revocation or key-rotation flow against live infrastructure.

Token, authorization, consent, authentication, interaction, security-generation, revocation and audit-state saves read their candidates without a row lock and use version conditions in primary updates; concurrent writes to the same observed version cannot both succeed. A lagging replica may return an older token or revocation state, and a stale write can fail with a version conflict. Other OAuth locking paths still require adaptation before this service can use strict read/write splitting.

An owner-local execution-proof helper can capture a verified USER's token digest and necessary identity facts without copying the bearer, then recheck them against current token, authorization, account, tenant membership, resource grant, security generation and signing-key state. It requires the source SERVICE's dedicated issue scope and exact resource binding. The helper fails closed unless it runs in a repeatable-read transaction against one verified PostgreSQL primary; replica and multi-primary deployments are not yet supported. This helper alone does not establish a delegated permission decision.

The internal execution-grant codec seals those facts with the existing realm-bound payload key and binds them to exact source/verifier identities, a purpose, run identifier, input fingerprint and bounded expiry. Its deterministic per-resource/run identifier stays the same across client replacement and reissuance so revocation can cover all copies. The recorded issuing SERVICE can be rechecked against its current client, resource grant, security generation, token and authorization revocations without retaining its bearer. A default-off owner-local service can issue and resolve envelopes only for explicitly configured tenant, issuer, source, verifier, purpose and user scopes; it rejects a changed policy, checks the revocation table and returns identity facts for Jianshen to authorize. With a fresh USER proof and a separately scoped source SERVICE, it can revoke the run identifier in the existing OAuth revocation table, atomically recording audit and Outbox events. The tombstone lasts at least eight hours or the original run deadline, whichever is later, plus clock skew and retention. When explicitly enabled, three internal POST endpoints issue, resolve and revoke these envelopes under separate SERVICE scopes; the source and verifier identities must match the configured binding. Issue and revoke accept a fresh USER proof only in the request, and the authority does not persist the bearer. The caller must protect the sealed ticket and independently arrange its durable storage; the verifier must compare the returned source tuple with its separately authenticated caller, compare the expected resource and intent, and authorize the resolved identity against current Jianshen permissions. These endpoints do not create grants or register permissions. Key replacement without the old key will make existing envelopes unreadable.

The starter offers an explicitly configured `HttpExecutionGrantClient` for one issuer, tenant and SERVICE registration. It sends each operation once with its own scope, rejects redirects, limits request/response sizes and the authority exchange time, validates response identity and avoids exposing remote bodies or credentials in exceptions. A timeout can leave a write outcome unknown. The same total deadline covers SERVICE token acquisition and the authority exchange. Bounded token operations share a finite no-queue pool in the existing OAuth client; timed-out operations that ignore interruption occupy a slot until they return. Workers receive only the SERVICE context, never the USER bearer. The client is not automatically enabled or configured.

SERVICE execution intents use the separate, default-off `egon.tianquan-shoubing.service-execution-grants` bindings and the `service-execution-grants:issue`, `:resolve` and `:revoke` internal endpoints. Each binding fixes the tenant and issuer, the issuing source, the original SERVICE subject, an independent verifier, the purpose, required SERVICE scopes, optional Session scopes and maximum lifetime. The original SERVICE bearer is accepted only for issue and is not retained; resolution rechecks its recorded token, client credential version, resource grant and revocation facts as well as the issuing source. The configured source can revoke its own sealed intent without a fresh subject bearer, including after its expiry. `HttpExecutionGrantClient` exposes `issueService`, `resolveService` and `revokeService` with separate least-privilege scopes. These endpoints require one verified primary and do not register or grant permissions; the verifier must still authorize the attested SERVICE against current Jianshen policy and bind the decision to the exact run.

Subject revocation creates per-tenant durable tasks in the directory transaction. Tasks for the same subject and tenant wait for their predecessors, and target security-event receipts prevent later outbox deliveries from being acknowledged first. Shoubing enables recovery of retryable outbox messages after their attempt budget is exhausted; permanent failures remain dead. Browser password changes use a directory receipt so a retry after the password commit does not change it again.

For a multi-primary rollout, install the matching Components version, route password-change receipts with the identity directory, subject-delivery receipts with their tenant security state, and resource fences with the platform resource table. Apply the managed manifests to every primary. Stop older writers and dispatchers during the upgrade, and drain or reconcile already queued subject events before starting the new ordered chain: earlier versions do not create the new receipts or enforce their ordering. Resource-grant changes hold a platform fence while a separate owning-shard transaction commits; configure sufficient pool capacity for both connections. Supply the approved previous routing fingerprint when changing topology. These code paths still require real PostgreSQL primary/replica acceptance; the checked-in example remains a single-primary topology.

Resource-grant and client resource-URI mutations join an existing transaction only when all writes belong to the same primary group; the local-write guard rejects a cross-group transaction. Outside an existing transaction, the platform fence and owning-shard write use separate transactions. An all-in-one permission bootstrap spanning primary groups requires a separately coordinated provisioning workflow.

## Build

Requires Java 25 and the included Maven Wrapper. The shared parent manages Spring Boot 4.1.2. Once the 0.0.1 dependencies are published:

```bash
./mvnw -B -ntp test-compile
```

Before the first Central publication, clone the eight Java repositories next to one another and bootstrap their artifact graph explicitly:

```bash
bash ../Stellar-Enclosure-Parent/scripts/bootstrap-workspace.sh \
  --workspace "$(cd .. && pwd)" \
  --local-repository "$HOME/.m2/repository"

# Resolve subsequent Maven commands and generator subprocesses from this same cache.
export MAVEN_ARGS="${MAVEN_ARGS:-} -Dmaven.repo.local=$HOME/.m2/repository"
```

The bootstrap installs parent/BOM models before building components and business starters in Maven reactor order. It compiles test sources and installs packages with runtime tests disabled. It never runs applications, databases, containers, browsers, or deploy.

## Publish to Maven Central

Publishes the Shoubing parent, core, RPC contract and Starter. Admin and the gateway adapter remain internal and are excluded. Requires the published platform parent and Components.

Run these commands from this repository. Configure a Central Portal token under Maven server ID `central` and a local GPG signing key; credentials stay outside Git. See the [credential setup and initial dependency order](https://github.com/Stellar-Enclosure/Stellar-Enclosure-Parent/blob/main/docs/first-release.md).

```bash
# Verify release artifacts locally; signing and upload are disabled.
./mvnw -B -ntp -Prelease -Dgpg.skip=true -DskipITs -Dinvoker.skip=true -Darchetype.test.skip=true clean verify

# Sign and publish this repository's public artifacts.
./mvnw -B -ntp -Prelease -DskipITs -Dinvoker.skip=true -Darchetype.test.skip=true clean deploy
```

Unit tests remain enabled. `release` attaches sources, Javadoc and GPG signatures, then publishes through the Central Portal. Ordinary builds and Git pushes do not publish. Each published GAV is immutable: use a new version for changed content, and use `-pl` to select only unpublished modules after a partial release. Before the first release, use the Build section's local bootstrap or publish the prerequisite artifacts first; bootstrap installation alone does not publish dependencies.

## Compatibility and publication

Java packages/classes, Bean names, configuration keys, OAuth/RPC identities, APIs, and database ownership are retained. Existing SQL and DDL history are copied byte for byte. Artifact/build versions and necessary build paths change. A successful build does not imply application startup or live infrastructure acceptance.

Git pushes run validation only. Central and npm publication are separate user actions. CI defaults to initial source bootstrap; after publication set `STELLAR_USE_SOURCE_BOOTSTRAP=false` to consume published artifacts directly. Private organizations may supply the Actions secret `STELLAR_ENCLOSURE_READ_TOKEN` with repository read access.

Original MIT/LGPL licenses and author attribution are preserved.

### Permission manifest delivery

The `permission-producer` profile exports and verifies each final executable independently. See [permission build and controlled delivery](docs/permission-ci.md) for the exact toolchain pin, offline CI, candidate registration and deployment-qualified activation gates. Runtime startup and administrator grants are not CI side effects.

## SSO and signing-key lifecycle

`egon.tianquan-shoubing.oauth.authentication-ttl` controls the SSO lifetime (1 minute to 8 hours, default `PT8H`).
`oauth.key-rotation.period`, `prepublish`, and `schedule` control automatic rotation and the same publication delay is enforced for manual activation.
`oauth.key-rotation.verification-overlap` is optional. When omitted, retiring keys remain verifiable for the SSO lifetime plus `egon.tianquan-shoubing.clock-skew` (at least the existing 690-second access-token grace). An explicit overlap must be at least this long; invalid lifecycle settings fail at startup. Existing key expiry timestamps are preserved.

## Device sessions

`GET /api/v1/tianquan-shoubing/me/sessions` returns the current tenant account's client, platform, login time, expiry and peer address. `POST /api/v1/tianquan-shoubing/me/sessions/{sessionId}/revoke` revokes only that owner's selected session and its authorization families, including existing access and refresh tokens. Both endpoints use the verified principal's subject and tenant; callers cannot select another owner.

An SSO authentication may serve both a browser and an App. Each client receives an independent device session, and multiple resource grants from the same SSO/client share that session. Admission uses the existing realm database lock and transaction; the sixth session evicts the oldest active session. Expired/revoked sessions and stale subject/realm generations do not occupy a slot. Revoked sessions require fresh password authentication before the same client can sign in again. Account active-role selections remain in Jianshen and are shared by every device.

The single new managed migration is `db/egon-mp/V20261027_001__add_device_sessions.sql`; preceding migrations remain unchanged. It backfills existing USER grants without replacing credentials or deleting data, and revokes older excess sessions for accounts already above the five-session limit. Session metadata follows the existing retention job after linked families expire and their retention ends. Peer addresses use the servlet's resolved remote address; forwarded headers are not trusted by this feature.

Session listing uses `tianquan-shoubing:identity:self:read`. Revocation uses the new `tianquan-shoubing:identity:self:session-revoke` permission and matching OAuth scope. Deploy the updated API/web manifests and grant these through the existing role/client-resource workflow; declaring a permission does not grant it at runtime. No database, application or browser acceptance is implied by the unit tests and artifact builds.

## Audit delivery and retention

`oauth.audit.delivery.duration` measures the strict authority handoff through receipt validation, with fixed receiver and CONFIRMED/FAILED tags. It does not change the required committed remote receipt or separately measure database commit time.

The retention job keeps expired audit dead letters because expiry alone does not prove recovery or archival. It warns when such records are found; operators must investigate the existing durable inbox/dead-letter evidence before any separately designed archival or cleanup. Pending and processing inbox entries are not deleted by the existing SQL predicate. Existing retention limits and replay protections for OAuth transactions, tokens and receipts remain in force.
