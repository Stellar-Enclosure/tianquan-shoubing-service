package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthSecuritySnapshotBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

/** Reads committed PostgreSQL generations; no external publication is required to revoke access. */
@Component("oauthSecurityProjectionComponent")
@RequiredArgsConstructor
public class OAuthSecurityProjectionComponent {

    @Qualifier("oAuthSecurityStateRepository") private final OAuthSecurityStateRepository stateRepository;
    @Qualifier("oAuthRevocationRepository") private final OAuthRevocationRepository revocationRepository;
    @Qualifier("oAuthAuthorizationRepository") private final OAuthAuthorizationRepository authorizationRepository;
    @Qualifier("oAuthClientRepository") private final OAuthClientRepository clientRepository;
    @Qualifier("oAuthRealmRepository") private final OAuthRealmRepository realmRepository;
    @Qualifier("oauthManagementRealmResolver") private final OAuthManagementRealmResolver managementRealmResolver;
    @Qualifier("egonColaMybatisPlusClock") private final Clock clock;

    /** An outbox acknowledgement verifies a committed fact; it does not create that fact. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public void applyProjection(TrustedRealmBO realm, OAuthSecurityChangedEvent event) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        if (event == null || !realm.getIssuer().equals(event.issuer()) || !realm.getRealmKey().equals(event.realmKey())) {
            throw new IllegalArgumentException("OAUTH_SECURITY_EVENT_REALM_MISMATCH");
        }
        OAuthSecurityTargetEnum target = OAuthSecurityTargetEnum.fromCode(event.targetType());
        long revision;
        if (target.isSecurityStateTarget()) {
            revision = stateRepository.findByTarget(realm, target, event.targetKey())
                    .orElseThrow(() -> unavailable("OAUTH_SECURITY_STATE_MISSING")).getRevision();
        } else if (target.isRevocationTarget()) {
            var current = revocationRepository.findByTarget(realm, target, event.targetKey());
            if (current.isEmpty() && event.expiresAt() != null && !event.expiresAt().isAfter(clock.instant())) { return; }
            revision = current.orElseThrow(() -> unavailable("OAUTH_REVOCATION_STATE_MISSING")).getRevision();
        } else { throw new IllegalArgumentException("OAUTH_SECURITY_TARGET_INVALID"); }
        if (event.revision() > revision) { throw unavailable("OAUTH_SECURITY_EVENT_REVISION_AHEAD"); }
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public boolean isIssuerReady(TrustedRealmBO realm) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        try {
            return realmRepository.findByIssuer(realm).filter(value -> "ACTIVE".equals(value.getStatus())
                    && value.getActiveKid() != null).isPresent()
                    && stateRepository.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self")
                    .filter(OAuthSecurityStateBO::isEnabled).isPresent();
        } catch (DataAccessException unavailable) { return false; }
    }

    /** Initializes an empty authority only; missing generations with prior history fail closed. */
    @Transactional
    public long recover(TrustedRealmBO realm) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        OAuthRealmBO registered = realmRepository.findByRealmKeyForUpdate(realm)
                .orElseThrow(() -> unavailable("OAUTH_SECURITY_REALM_STATE_MISSING"));
        List<OAuthClientBO> clients = clientRepository.findAllByRealm(realm);
        boolean missingRealm = stateRepository.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self").isEmpty();
        List<OAuthClientBO> missingClients = clients.stream().filter(client -> stateRepository.findByTarget(
                realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId())).isEmpty()).toList();
        if ((missingRealm || !missingClients.isEmpty()) && hasSecurityHistory(realm)) {
            throw unavailable("OAUTH_SECURITY_GENERATION_STATE_INCOMPLETE");
        }
        if (missingRealm) { stateRepository.save(realm, initial(OAuthSecurityTargetEnum.REALM, "self",
                "ACTIVE".equals(registered.getStatus()), 0L), 0L); }
        for (OAuthClientBO client : missingClients) {
            stateRepository.save(realm, initial(OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId()),
                    client.getStatus() == OAuthClient.Status.ACTIVE, 0L), 0L);
        }
        return stateRepository.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self")
                .orElseThrow(() -> unavailable("OAUTH_SECURITY_STATE_MISSING")).getRevision();
    }

    @Transactional
    public void recoverRegisteredRealms() {
        for (OAuthRealmBO row : realmRepository.findAllByStoragePartition(managementRealmResolver.platformRealm())) {
            recover(trustedRealm(row));
        }
    }

    @Transactional
    public OAuthSecuritySnapshotBO snapshotForAuthorization(TrustedRealmBO realm, Long clientPk,
            String principalType, String subject) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        boolean user = "USER".equals(principalType);
        if (clientPk == null || clientPk <= 0 || !List.of("USER", "SERVICE").contains(principalType)
                || user != (subject != null && !subject.isBlank())) { throw unavailable("OAUTH_SECURITY_SNAPSHOT_INPUT_INVALID"); }
        // Every generation mutation uses this same realm-first lock order.
        realmRepository.findByRealmKeyForUpdate(realm).orElseThrow(() -> unavailable("OAUTH_SECURITY_REALM_STATE_MISSING"));
        var realmState = enabled(realm, OAuthSecurityTargetEnum.REALM, "self");
        var clientState = enabled(realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(clientPk));
        long revision = Math.max(realmState.getRevision(), clientState.getRevision());
        OAuthSecurityStateBO subjectState = null;
        if (user) {
            subjectState = stateRepository.findByTarget(realm, OAuthSecurityTargetEnum.SUBJECT, subject).orElse(null);
            if (subjectState == null) {
                for (String status : List.of("ACTIVE", "PENDING_CONSENT", "REVOKED", "EXPIRED", "CANCELLED")) {
                    if (!authorizationRepository.findByPrincipalName(realm, subject, status, 0L, 1).isEmpty()) {
                        throw unavailable("OAUTH_SECURITY_SUBJECT_STATE_MISSING_WITH_AUTHORIZATION");
                    }
                }
                subjectState = stateRepository.save(realm, initial(OAuthSecurityTargetEnum.SUBJECT, subject, true, revision), 0L);
            }
            if (!subjectState.isEnabled()) { throw invalidGrant("OAUTH_SECURITY_STATE_DISABLED"); }
            revision = Math.max(revision, subjectState.getRevision());
        }
        return OAuthSecuritySnapshotBO.builder().realmGeneration(realmState.getGeneration())
                .clientGeneration(clientState.getGeneration()).subjectGeneration(subjectState == null ? null : subjectState.getGeneration())
                .readyEpoch("postgresql:" + realm.getTrustVersion()).revision(revision).build();
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public void requireCurrentSnapshot(TrustedRealmBO realm, Long clientPk, String principalType,
            String subject, OAuthSecuritySnapshotBO expected) {
        var rows = stateRepository.findSnapshot(realm, clientPk, subject);
        boolean user = "USER".equals(principalType);
        if (rows.size() != (user ? 3 : 2) || rows.stream().anyMatch(value -> !value.isEnabled())) {
            throw invalidGrant("OAUTH_SECURITY_SNAPSHOT_STALE");
        }
        java.util.Map<OAuthSecurityTargetEnum, OAuthSecurityStateBO> values = new java.util.EnumMap<>(OAuthSecurityTargetEnum.class);
        rows.forEach(value -> values.put(value.getTargetType(), value));
        var realmState = values.get(OAuthSecurityTargetEnum.REALM);
        var clientState = values.get(OAuthSecurityTargetEnum.CLIENT);
        var subjectState = values.get(OAuthSecurityTargetEnum.SUBJECT);
        if (realmState == null || clientState == null || user != (subjectState != null)) {
            throw invalidGrant("OAUTH_SECURITY_SNAPSHOT_STALE");
        }
        var current = OAuthSecuritySnapshotBO.builder().realmGeneration(realmState.getGeneration())
                .clientGeneration(clientState.getGeneration()).subjectGeneration(subjectState == null ? null : subjectState.getGeneration()).build();
        if (expected == null || current.getRealmGeneration() != expected.getRealmGeneration()
                || current.getClientGeneration() != expected.getClientGeneration()
                || !Objects.equals(current.getSubjectGeneration(), expected.getSubjectGeneration())) {
            throw invalidGrant("OAUTH_SECURITY_SNAPSHOT_STALE");
        }
    }

    private OAuthSecurityStateBO enabled(TrustedRealmBO realm, OAuthSecurityTargetEnum target, String key) {
        var value = stateRepository.findByTarget(realm, target, key).orElseThrow(() -> unavailable("OAUTH_SECURITY_STATE_MISSING"));
        if (!value.isEnabled()) { throw invalidGrant("OAUTH_SECURITY_STATE_DISABLED"); }
        return value;
    }

    private boolean hasSecurityHistory(TrustedRealmBO realm) {
        return !authorizationRepository.findExpiredBefore(realm, Instant.parse("9999-12-31T23:59:59Z"), 0L, 1).isEmpty()
                || !revocationRepository.findByRevisionAfter(realm, 0L, 0L, 1).isEmpty();
    }

    private static OAuthSecurityStateBO initial(OAuthSecurityTargetEnum target, String key, boolean enabled, long revision) {
        return OAuthSecurityStateBO.builder().version(0L).targetType(target).targetKey(key).generation(0L)
                .enabled(enabled).revision(revision).reasonCode("INITIALIZED").build();
    }

    private static TrustedRealmBO trustedRealm(OAuthRealmBO value) {
        var realm = TrustedRealmBO.builder().issuer(value.getIssuer()).realmKey(value.getRealmKey()).realmType(value.getRealmType())
                .storagePartitionId(value.getStoragePartitionId()).businessTenantId(value.getBusinessTenantId())
                .trustVersion(value.getTrustVersion()).build();
        realm.validateTrustedPartition(); return realm;
    }

    private static OAuth2AuthenticationException unavailable(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", code, null));
    }

    private static OAuth2AuthenticationException invalidGrant(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_grant", code, null));
    }
}
