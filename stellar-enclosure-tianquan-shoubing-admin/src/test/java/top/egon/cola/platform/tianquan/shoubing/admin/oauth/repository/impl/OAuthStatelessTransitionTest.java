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
