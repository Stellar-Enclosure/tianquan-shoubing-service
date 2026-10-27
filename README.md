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
