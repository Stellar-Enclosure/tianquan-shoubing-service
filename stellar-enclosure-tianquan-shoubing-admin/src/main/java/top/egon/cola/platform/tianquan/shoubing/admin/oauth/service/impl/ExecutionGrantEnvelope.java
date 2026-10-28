package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Immutable, encrypted identity evidence and the exact services and run it is allowed to bind. */
record ExecutionGrantEnvelope(int schemaVersion, String grantId, ServiceBinding source, ServiceBinding verifier,
        String purpose, String intentId, String bindingSha256, boolean sessionRequired,
        Instant notBefore, Instant expiresAt, StoredUserExecutionProof user) {

    ExecutionGrantEnvelope {
        source = Objects.requireNonNull(source, "source");
        verifier = Objects.requireNonNull(verifier, "verifier");
        user = Objects.requireNonNull(user, "user");
        if (schemaVersion != 1 || grantId == null || !grantId.matches("9[0-9]{62}")
                || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || !uuid(intentId)
                || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}")
                || notBefore == null || expiresAt == null || !expiresAt.isAfter(notBefore)
                || notBefore.isBefore(Instant.ofEpochSecond(user.authenticationTime()))
                || Duration.between(notBefore, expiresAt).compareTo(Duration.ofHours(8)) > 0
                || !source.resourceUri().equals(user.resourceUri())
                || source.clientPk() == verifier.clientPk() || source.resourceUri().equals(verifier.resourceUri())
                || expiresAt.isAfter(Instant.ofEpochSecond(user.authenticationExpiresAt()))
                || expiresAt.isAfter(Instant.ofEpochSecond(user.authorizationExpiresAt()))
                || expiresAt.isAfter(user.tokenRetainUntil())
                || !grantId.equals(OpaqueExecutionGrantCodec.grantId(user, source, purpose, intentId))) {
            throw new IllegalArgumentException("EXECUTION_GRANT_ENVELOPE_INVALID");
        }
    }

    record ServiceBinding(long clientPk, String clientId, String appId, String businessCode,
                          String applicationCode, String environment, String resourceUri) {
        ServiceBinding {
            if (clientPk <= 0 || !text(clientId, 128) || !text(appId, 128) || !text(businessCode, 128)
                    || !text(applicationCode, 128) || !text(environment, 128)) {
                throw new IllegalArgumentException("EXECUTION_GRANT_SERVICE_INVALID");
            }
            secureUri(resourceUri);
        }

        /** Compares a previously authenticated SERVICE caller with this exact configured binding. */
        boolean matches(OAuthAuthorityService.Caller caller, StoredUserExecutionProof user, String scope, Instant now) {
            if (caller == null || caller.realm() == null || caller.principal() == null || caller.sourceResource() == null
                    || user == null || scope == null || scope.isBlank() || now == null) return false;
            try { caller.realm().validateTrustedPartition(); }
            catch (IllegalArgumentException | NullPointerException invalid) { return false; }
            var principal = caller.principal();
            return caller.clientPk() == clientPk && clientId.equals(principal.clientId()) && appId.equals(principal.appId())
                    && businessCode.equals(principal.sourceBizCode()) && applicationCode.equals(principal.sourceAppCode())
                    && environment.equals(principal.sourceEnvironment())
                    && resourceUri.equals(caller.sourceResource().toASCIIString())
                    && user.issuer().equals(caller.realm().getIssuer().toASCIIString())
                    && Long.valueOf(user.tenantId()).equals(caller.realm().getBusinessTenantId())
                    && user.issuerTrustVersion() == caller.realm().getTrustVersion()
                    && principal.scopeContext() == ServiceTokenContext.TENANT
                    && Long.toString(user.tenantId()).equals(principal.tenantId())
                    && principal.expiresAt().isAfter(now) && principal.scopes().contains(scope);
        }

        @Override public String toString() { return "ServiceBinding[redacted]"; }
    }

    private static boolean uuid(String value) {
        try { return value != null && UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException invalid) { return false; }
    }

    private static boolean text(String value, int maximum) {
        return value != null && !value.isBlank() && value.length() <= maximum && value.equals(value.trim())
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static void secureUri(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.normalize().equals(uri)
                    || value.length() > 2048) throw new IllegalArgumentException();
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("EXECUTION_GRANT_URI_INVALID");
        }
    }

    @Override public String toString() { return "ExecutionGrantEnvelope[redacted]"; }
}
