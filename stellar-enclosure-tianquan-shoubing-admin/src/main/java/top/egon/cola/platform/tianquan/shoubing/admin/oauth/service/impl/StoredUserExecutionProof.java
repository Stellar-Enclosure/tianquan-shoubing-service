package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;

import java.net.URI;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;

/** Owner-local evidence captured from a verified USER token; it is never a bearer credential. */
record StoredUserExecutionProof(String issuer, long tenantId, long issuerTrustVersion, String subject,
        String resourceUri, long clientPk, String clientId, long authorizationId, String tokenDigest,
        String tokenJti, String signingKeyId, Set<String> scopes, long realmGeneration, long clientGeneration,
        long subjectGeneration, String authenticationJtiDigest, String acr, long authenticationTime,
        long authenticationExpiresAt, long authorizationExpiresAt, long refreshGeneration, Instant tokenRetainUntil) {

    StoredUserExecutionProof {
        secureUri(issuer);
        secureUri(resourceUri);
        if (tenantId <= 0 || issuerTrustVersion < 0 || !text(subject, 128) || clientPk <= 0
                || !text(clientId, 128) || authorizationId <= 0 || !hash(tokenDigest) || !hash(authenticationJtiDigest)
                || tokenJti == null || !tokenJti.matches("[1-9][0-9]{0,18}")
                || signingKeyId == null || !signingKeyId.matches("[A-Za-z0-9_-]{1,128}")
                || realmGeneration < 0 || clientGeneration < 0 || subjectGeneration < 0
                || !text(acr, 64) || authenticationTime < 0 || authenticationExpiresAt <= authenticationTime
                || authorizationExpiresAt <= authenticationTime || refreshGeneration < 0 || tokenRetainUntil == null
                || scopes == null || scopes.isEmpty() || scopes.size() > 64
                || scopes.stream().anyMatch(scope -> scope == null || !scope.matches("[A-Za-z0-9:._-]{1,128}"))) {
            throw new IllegalArgumentException("EXECUTION_USER_PROOF_INVALID");
        }
        scopes = Set.copyOf(new TreeSet<>(scopes));
    }

    void requireRealm(TrustedRealmBO realm) {
        if (realm == null) throw new IllegalArgumentException("EXECUTION_USER_REALM_INVALID");
        realm.validateTrustedPartition();
        if (!issuer.equals(realm.getIssuer().toASCIIString()) || !Long.valueOf(tenantId).equals(realm.getBusinessTenantId())
                || issuerTrustVersion != realm.getTrustVersion()) {
            throw new IllegalArgumentException("EXECUTION_USER_REALM_MISMATCH");
        }
    }

    private static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }

    private static boolean text(String value, int max) {
        return value != null && !value.isBlank() && value.length() <= max && value.equals(value.trim())
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static void secureUri(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.normalize().equals(uri)
                    || value.length() > 2048) throw new IllegalArgumentException();
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("EXECUTION_USER_URI_INVALID");
        }
    }

    @Override public String toString() { return "StoredUserExecutionProof[redacted]"; }
}
