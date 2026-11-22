package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthConsentBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasConsentConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthConsentRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TenantConsentResourceBindingTest {
    private static final String FIRST = "https://api.example.test/orders";
    private static final String SECOND = "https://api.example.test/invoices";
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmKey("tenant:7").realmType(RealmTypeEnum.TENANT).storagePartitionId(7L)
            .businessTenantId(7L).trustVersion(1L).build();
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthConsentRepository consents = mock(OAuthConsentRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthBrowserInteractionComponent interactions = mock(OAuthBrowserInteractionComponent.class);
    private final Map<String, OAuthConsentBO> rows = new HashMap<>();
    private final OAuth2AuthorizationConsent input = OAuth2AuthorizationConsent.withId("5", "alice").scope("openid").build();
    private final TenantConsentServiceImpl service = new TenantConsentServiceImpl(issuers, consents, clients,
            Mappers.getMapper(SasConsentConverter.class), Clock.fixed(Instant.parse("2026-11-22T00:00:00Z"), ZoneOffset.UTC),
            realms, states, interactions);

    @BeforeEach
    void prepare() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        when(clients.findById(realm, 5L)).thenReturn(Optional.of(OAuthClientBO.builder().id(5L)
                .status(OAuthClient.Status.ACTIVE).allowedScopes(List.of("openid")).build()));
        when(consents.findConsent(eq(realm), eq(5L), eq("alice"), anyString()))
                .thenAnswer(call -> Optional.ofNullable(rows.get(call.getArgument(3))));
        when(consents.save(eq(realm), any(), anyLong())).thenAnswer(call -> {
            OAuthConsentBO row = call.getArgument(1);
            if (row.getId() == null) row.setId(20L + rows.size());
            rows.put(row.getResourceUri(), row);
            return row;
        });
    }

    @AfterEach
    void cleanup() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void persistsAndRevokesOnlyTheVerifiedInteractionResource() {
        select(FIRST, 5L);
        service.save(input);
        assertThat(rows.get(FIRST).getResourceUri()).isEqualTo(FIRST);
        select(SECOND, 5L);
        assertThat(service.findById("5", "alice")).isNull();
        service.save(input);
        assertThat(rows).hasSize(2);
        assertThat(rows.get(SECOND).getVersion()).isZero();
        select(FIRST, 5L);
        service.save(input);
        assertThat(rows.get(FIRST).getVersion()).isEqualTo(1);
        assertThat(rows.get(SECOND).getVersion()).isZero();
        service.remove(input);
        assertThat(rows.get(FIRST).getStatus()).isEqualTo("REVOKED");
        assertThat(rows.get(SECOND).getStatus()).isEqualTo("ACTIVE");
        select(SECOND, 5L);
        assertThat(service.findById("5", "alice").getScopes()).containsExactly("openid");
    }

    @Test
    void rejectsAClientOutsideTheVerifiedInteraction() {
        select(FIRST, 6L);
        assertThatThrownBy(() -> service.save(input)).isInstanceOf(IllegalArgumentException.class)
                .hasMessage("OAUTH_CONSENT_INTERACTION_MISMATCH");
        verify(consents, never()).save(any(), any(), anyLong());
    }

    @Test
    void requiresVerifiedBrowserInteractionContext() {
        RequestContextHolder.resetRequestAttributes();
        assertThatThrownBy(() -> service.save(input)).isInstanceOf(IllegalStateException.class)
                .hasMessage("OAUTH_CONSENT_INTERACTION_REQUIRED");
        verify(consents, never()).save(any(), any(), anyLong());
    }

    private void select(String resource, long client) {
        when(interactions.require(any(), eq(false))).thenReturn(OAuthInteractionBO.builder()
                .clientPk(client).resourceUri(resource).purpose("AUTHORIZATION").build());
    }
}
