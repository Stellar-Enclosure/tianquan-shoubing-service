package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;

/** Owner-local SERVICE evidence; it contains a token digest, never a bearer credential. */
record StoredServiceExecutionProof(String issuer, long tenantId, long issuerTrustVersion, String subject,
        String resourceUri, long resourceVersion, long clientPk, String clientId, String appId,
        String businessCode, String applicationCode, String environment, String sourceResourceUri, String credentialId,
        long authorizationId, String tokenDigest, String tokenJti, String signingKeyId, Set<String> scopes,
        long realmGeneration, long clientGeneration, Instant tokenRetainUntil) {

    StoredServiceExecutionProof {
        secureUri(issuer); secureUri(resourceUri); secureUri(sourceResourceUri);
        if (tenantId <= 0 || issuerTrustVersion < 0 || resourceVersion < 0 || clientPk <= 0
                || !text(subject, 128) || !subject.equals(clientId) || !text(appId, 128) || !text(businessCode, 128)
                || !text(applicationCode, 128) || !text(environment, 128) || !text(credentialId, 128)
                || authorizationId <= 0 || tokenDigest == null || !tokenDigest.matches("[0-9a-f]{64}")
                || tokenJti == null || !tokenJti.matches("[1-9][0-9]{0,18}")
                || signingKeyId == null || !signingKeyId.matches("[A-Za-z0-9_-]{1,128}")
                || realmGeneration < 0 || clientGeneration < 0 || tokenRetainUntil == null
                || scopes == null || scopes.isEmpty() || scopes.size() > 64
                || scopes.stream().anyMatch(scope -> scope == null || !scope.matches("[A-Za-z0-9:._-]{1,128}"))) {
            throw new IllegalArgumentException("EXECUTION_SERVICE_PROOF_INVALID");
        }
        scopes = Set.copyOf(new TreeSet<>(scopes));
    }

    void requireRealm(TrustedRealmBO realm) {
        if (realm == null) throw new IllegalArgumentException("EXECUTION_SERVICE_REALM_INVALID");
        realm.validateTrustedPartition();
        if (!issuer.equals(realm.getIssuer().toASCIIString()) || !Long.valueOf(tenantId).equals(realm.getBusinessTenantId())
                || issuerTrustVersion != realm.getTrustVersion()) throw new IllegalArgumentException("EXECUTION_SERVICE_REALM_MISMATCH");
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
        } catch (RuntimeException invalid) { throw new IllegalArgumentException("EXECUTION_SERVICE_URI_INVALID"); }
    }
    @Override public String toString() { return "StoredServiceExecutionProof[redacted]"; }
}
