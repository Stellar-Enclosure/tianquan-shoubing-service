package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.impl;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthAuthenticationConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthInteractionConverter;

import static org.junit.jupiter.api.Assertions.*;

class OAuthStatelessTransitionTest {

    private static final Instant NOW = Instant.parse("2026-10-23T12:00:00Z");

    @Test
    void passwordAuthenticationCannotCreateStrongerAssurance() {
        var value = authentication().acr("STRONG").build();
        assertThrows(IllegalArgumentException.class,
                () -> OAuthAuthenticationRepositoryImpl.requireTransition(null, value));
    }

    @Test
    void authenticationExpiryCannotSlideButSafeRetentionCanGrow() {
        var original = authentication().build();
        var row = Mappers.getMapper(OAuthAuthenticationConverter.class).toSource(original);
        assertThrows(IllegalArgumentException.class, () -> OAuthAuthenticationRepositoryImpl.requireTransition(row,
                original.toBuilder().expiresAt(NOW.plusSeconds(28_801)).build()));
        assertDoesNotThrow(() -> OAuthAuthenticationRepositoryImpl.requireTransition(row,
                original.toBuilder().retainUntil(NOW.plusSeconds(200_000)).build()));
    }

    @Test
    void revokedAuthenticationCannotBeReopened() {
        var revoked = authentication().status("REVOKED").revokedAt(NOW.plusSeconds(1)).reasonCode("LOGOUT").build();
        var row = Mappers.getMapper(OAuthAuthenticationConverter.class).toSource(revoked);
        assertThrows(IllegalArgumentException.class, () -> OAuthAuthenticationRepositoryImpl.requireTransition(row,
                revoked.toBuilder().status("ACTIVE").revokedAt(null).reasonCode(null).build()));
    }

    @Test
    void interactionApprovalCannotExceedRequestedScope() {
        var value = interaction().approvedScopes(List.of("orders:write")).build();
        assertThrows(IllegalArgumentException.class, () -> OAuthInteractionRepositoryImpl.requireTransition(null, value));
    }

    @Test
    void consumedInteractionCannotBeUsedAgainOrRebound() {
        var consumed = interaction().state("CONSUMED").consumedAt(NOW.plusSeconds(2)).build();
        var row = Mappers.getMapper(OAuthInteractionConverter.class).toSource(consumed);
        assertThrows(IllegalArgumentException.class, () -> OAuthInteractionRepositoryImpl.requireTransition(row,
                consumed.toBuilder().state("AUTHENTICATED").consumedAt(null).build()));
        assertThrows(IllegalArgumentException.class, () -> OAuthInteractionRepositoryImpl.requireTransition(row,
                consumed.toBuilder().authenticationJtiDigest("d".repeat(64)).build()));
    }

    @Test
    void consentProgressPreservesBrowserClientAndIdentityBinding() {
        var pending = interaction().authenticationJtiDigest("a".repeat(64)).build();
        var row = Mappers.getMapper(OAuthInteractionConverter.class).toSource(pending);
        assertDoesNotThrow(() -> OAuthInteractionRepositoryImpl.requireTransition(row,
                pending.toBuilder().state("CONSENT_REQUIRED").approvedScopes(List.of("openid")).build()));
        assertThrows(IllegalArgumentException.class, () -> OAuthInteractionRepositoryImpl.requireTransition(row,
                pending.toBuilder().clientBrowserBindingDigest("d".repeat(64)).build()));
        assertThrows(IllegalArgumentException.class, () -> OAuthInteractionRepositoryImpl.requireTransition(row,
                pending.toBuilder().authenticationJtiDigest("d".repeat(64)).build()));
    }

    @Test
    void competingInteractionWritesUseTheObservedVersionWithoutLockingTheRead() throws Exception {
        var mapper = org.mockito.Mockito.mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthInteractionMapper.class);
        var converter = Mappers.getMapper(OAuthInteractionConverter.class);
        var observed = interaction().id(201L).version(0L).build();
        var row = converter.toSource(observed);
        row.setId(201L); row.setTenantId(1001L); row.setVersion(0L);
        var request = observed.toBuilder().version(1L).state("CONSUMED").consumedAt(NOW.plusSeconds(1)).build();
        var realm = top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO.builder()
                .issuer(java.net.URI.create("https://auth.example/tenants/1001")).realmKey("tenant:1001")
                .realmType(top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum.TENANT)
                .storagePartitionId(1001L).businessTenantId(1001L).trustVersion(0L).build();
        var barrier = new java.util.concurrent.CyclicBarrier(2);
        var won = new java.util.concurrent.atomic.AtomicBoolean();
        org.mockito.Mockito.when(mapper.selectByKey(1001L, "interaction")).thenAnswer(call -> {
            barrier.await(5, java.util.concurrent.TimeUnit.SECONDS);
            return row;
        });
        org.mockito.Mockito.when(mapper.updateExpectedVersion(org.mockito.ArgumentMatchers.eq(1001L),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.eq(0L)))
                .thenAnswer(call -> won.compareAndSet(false, true) ? 1 : 0);
        var repository = new OAuthInteractionRepositoryImpl(mapper,
                new top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties(),
                converter, () -> "service:tianquan-shoubing", java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC));
        java.util.concurrent.Callable<Boolean> save = () -> {
            try {
                repository.save(realm, request, 0L);
                return true;
            } catch (org.springframework.dao.OptimisticLockingFailureException conflict) {
                return false;
            }
        };
        try (var workers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = workers.submit(save);
            var second = workers.submit(save);
            assertNotEquals(first.get(10, java.util.concurrent.TimeUnit.SECONDS),
                    second.get(10, java.util.concurrent.TimeUnit.SECONDS));
        }
        org.mockito.Mockito.verify(mapper, org.mockito.Mockito.never()).selectByKeyForUpdate(1001L, "interaction");
    }

    private static OAuthAuthenticationBO.OAuthAuthenticationBOBuilder authentication() {
        return OAuthAuthenticationBO.builder().jtiDigest("a".repeat(64)).subject("subject")
                .browserBindingDigest("b".repeat(64)).subjectGeneration(0L).realmGeneration(0L)
                .authenticatedAt(NOW).acr("PASSWORD").status("ACTIVE")
                .expiresAt(NOW.plusSeconds(28_800)).retainUntil(NOW.plusSeconds(115_200));
    }

    private static OAuthInteractionBO.OAuthInteractionBOBuilder interaction() {
        return OAuthInteractionBO.builder().interactionId("interaction").purpose("AUTHORIZATION")
                .clientPk(1L).resourceUri("https://api.example/orders").redirectUri("https://ui.example/callback")
                .requestDigest("a".repeat(64)).requestCiphertext("ENC:request")
                .browserBindingDigest("b".repeat(64)).clientBrowserBindingDigest("c".repeat(64))
                .csrfDigest("e".repeat(64)).codeChallenge("k".repeat(43)).codeChallengeMethod("S256")
                .requestedScopes(List.of("openid", "orders:read")).approvedScopes(List.of())
                .state("PENDING").expiresAt(NOW.plusSeconds(300)).retainUntil(NOW.plusSeconds(86_700));
    }
}
