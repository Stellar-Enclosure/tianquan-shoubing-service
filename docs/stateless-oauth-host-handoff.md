# Stateless OAuth host configuration handoff

This note records the S04–S06 configuration contract for the approved 2026-10-23 implementation. It is not a deployment or runtime acceptance record. No application, database, container, or browser has been started for this implementation.

## Identity owner

The IdP Admin provides `OAuthLocalAuthorityConfiguration` and an `IdentityAuthorityClientResolver` that terminates at `OAuthAuthorityService` and the local PostgreSQL repositories. It must not configure an HTTP authority route back to itself.

The following inputs must be supplied by the deployment's explicit trust configuration:

| Property | Required meaning |
| --- | --- |
| `egon.cola.platform.tianquan.shoubing.trusted-issuers.<exact-issuer>.issuer` | Exact, canonical HTTPS issuer; the map key is the same issuer URI |
| `...trusted-issuers.<exact-issuer>.jwks-uri` | The registered issuer's fixed HTTPS JWK endpoint |
| `...trusted-issuers.<exact-issuer>.realm-key` | The registered realm key |
| `...trusted-issuers.<exact-issuer>.realm-type` | `TENANT` or `PLATFORM` |
| `...trusted-issuers.<exact-issuer>.tenant-id` | Positive decimal business tenant for `TENANT`; absent for `PLATFORM` |
| `...trusted-issuers.<exact-issuer>.status` | `ACTIVE` for issuers admitted by this host |
| `...trusted-issuers.<exact-issuer>.trust-version` | Non-negative version of that trust tuple |
| `egon.cola.platform.tianquan.shoubing.resource-server-id` | This host's registered resource identifier |
| `egon.cola.platform.tianquan.shoubing.resource-uri` | This host's registered HTTPS audience |
| `egon.cola.platform.tianquan.shoubing.usage-observation.enabled` | `true` for the managed verifier |
| `egon.cola.platform.tianquan.shoubing.usage-observation.fallback-issuer` | One configured active issuer for secret-free authentication failures |
| `egon.tianquan-shoubing.oauth.public-origin` | Fixed HTTPS public IdP origin, with no path/query/fragment |
| `egon.tianquan-shoubing.oauth.authentication-ttl` | Default `PT8H`; accepted range `PT1M` through `PT8H` |

The current application YAML still contains the prior single-issuer `issuer`/`jwk-set-uri` values. Those values alone do not satisfy the finite multi-issuer configuration. The actual deployment tuples must be supplied during the shared host-configuration step; sample or inferred tenant identities are not substituted here.

The IdP resource's `managementClientId` must name an active client in each admitted realm. The local SQL audit adapter derives its producer identity from that registration and validates the event resource and issuer before accepting it.

## Consumer hosts

Servlet and GatewayAdapter consumers use the Starter's fixed `IdentityAuthorityClientResolver`. For each active trusted issuer, configure exactly one binding under `egon.cola.platform.tianquan.shoubing.authority.bindings.<alias>` with `issuer`, `source-resource`, `registration-id`, `audience`, `context`, `tenant-id`, and `scopes`. `source-resource` is the protected upstream resource, while `audience` is the IdP AUTH-07 resource. `app-id` comes from the existing `service-client.app-id`. Every active issuer needs the host resource binding, and a Gateway additionally needs a binding for each upstream resource. The fixed `authority.base-uri` is HTTPS; `authority.timeout` defaults to `PT2S` and cannot exceed `PT5S`.

Required dedicated SERVICE capabilities are `tianquan-shoubing:security-state:resolve` and `tianquan-shoubing:audit:append`. EDGE refresh proof adds `tianquan-shoubing:refresh-context:resolve`. Spring client registrations and `service-client.credential-versions` must refer to the matching issuer and application context. These values and credentials are deployment inputs, not values derived from the incoming USER JWT.

## Removed authority configuration

`application.yml` and `application-local.yml` no longer configure identity revocation Redis endpoints or epochs, audit Redis streams, disk spool paths, HMAC files, spool replay, or identity projection key prefixes. Existing spool files are not deleted. Audit scheduling now drains PostgreSQL inbox rows. Provider readiness checks the SQL Outbox and audit readiness instead of a Redis connection. The unused Common two-level cache is disabled for this host.

The remaining `egon.cola.platform.tianquan.jianshen.runtime` Redis settings are an explicitly incomplete RBAC host integration, pending the R owner's database/HTTP runtime contract. They must be replaced in the shared S27/S29 host step; they are not an accepted identity fallback. The RBAC authorization endpoint also requires its final configured service identity and fixed target binding.

## Native browser contract

The IdP uses secure, HttpOnly, SameSite=Lax `__Host-` cookies for browser binding, short SQL interaction, CSRF, and the independent authentication JWT. No Spring HttpSession is needed. Authorization and consent interactions expire within five minutes. Password authentication remains `PASSWORD`; a password recheck does not claim stronger assurance.

Browser-bound clients pass a 64-character lowercase SHA-256 `browser_binding` in authorization, code exchange, and refresh exchange. This binds the client's browser context to its authorization family and is separate from the IdP browser cookie. The authentication JWT has its own `authn+jwt` type, `IDP_AUTHENTICATION` purpose, and IdP-only audience; business refresh does not extend its absolute expiry.

Client create/update and read APIs now expose `browserBound` and `postLogoutRedirectUris`. Creation defaults to an unbound client and an empty logout list. An update that omits these optional fields preserves their existing values. SERVICE clients reject browser binding/logout redirects; changes to either security setting advance the client security generation through the existing revocation transaction. Current EDGE clients must be explicitly registered with `browserBound=true`.

The native `/tenants/{tenantId}/password-change` route requires a restricted SQL interaction and returns to sign-in after a successful password change. `/tenants/{tenantId}/logout` requires a short logout interaction and CSRF-confirmed POST; it closes the current authentication and linked grants. Post-logout redirects must be explicitly registered on the selected client. Current-application revocation continues through the native authenticated token-revocation endpoint.

## Validation boundary

The native filters, converters, providers, JWT signatures, and transaction behavior are exercised with focused unit/MockMvc tests. The PostgreSQL integration profile requires an explicitly configured test database and has not been run here. Host startup, live migration, real SQL concurrency, browser cookies across origins, reverse proxy routing, and end-to-end SSO remain separate runtime checks.
