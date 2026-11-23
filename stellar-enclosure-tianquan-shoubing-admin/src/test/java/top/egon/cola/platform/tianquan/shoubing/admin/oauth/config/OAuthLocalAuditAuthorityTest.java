package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditReceiptBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl.OAuthAuditDeliveryService;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceServerStatus;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OAuthLocalAuditAuthorityTest {
    private static final Instant NOW = Instant.parse("2026-11-23T01:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final URI RESOURCE = URI.create("https://api.example/shoubing");
    private static final String OWNER_CLIENT_ID = "shoubing-owner";
    private final TrustedRealmBO tenant = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:1001")
            .realmType(RealmTypeEnum.TENANT).storagePartitionId(1001L).businessTenantId(1001L).trustVersion(0L).build();
    private final TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
            .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1000L).trustVersion(0L).build();
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthResourceRepository resources = mock(OAuthResourceRepository.class);
    private final OAuthAuditDeliveryService audits = mock(OAuthAuditDeliveryService.class);
    private final OAuthManagementRealmResolver management = mock(OAuthManagementRealmResolver.class);
    private final TrustedIssuerRegistry trust = mock(TrustedIssuerRegistry.class);
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private TokenUsageAuditComponent producer;

    @BeforeEach
    void prepare() {
        var properties = new IdpStarterProperties();
        properties.setResourceUri(RESOURCE);
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var authority = new OAuthAuthorityService(mock(OAuthAuthorityTokenVerifier.class), mock(OAuthAuthorizationRepository.class),
                clients, mock(OAuthTokenRepository.class), mock(OAuthAuthenticationRepository.class),
                mock(OAuthSecurityStateRepository.class), mock(OAuthRevocationRepository.class), resources,
                mock(OAuthGrantRepository.class), mock(IdentityUserRepository.class), mock(TenantMembershipPort.class),
                management, audits, properties, clock);
        when(management.platformRealm()).thenReturn(platform);
        when(resources.findByResourceUri(platform, RESOURCE)).thenReturn(Optional.of(resource()));
        when(clients.findById(platform, 31L)).thenReturn(Optional.of(owner()));
        when(trust.findByIssuer(ISSUER.toASCIIString())).thenReturn(Optional.of(new TrustedIssuerRegistry.TrustedIssuerVO(
                ISSUER, URI.create("https://idp.example/tenants/1001/.well-known/jwks.json"), "tenant:1001",
                TrustedIssuerRegistry.RealmType.TENANT, "1001", TrustedIssuerRegistry.Status.ACTIVE, 0L)));
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(tenant);
        when(audits.append(eq(tenant), eq(31L), eq(ISSUER.toASCIIString()), eq(RESOURCE.toASCIIString()), any()))
                .thenAnswer(call -> receipt(call.getArgument(4)));
        var resolver = new OAuthLocalAuthorityConfiguration().identityAuthorityClientResolver(authority, issuers, trust);
        validator.afterPropertiesSet();
        producer = new TokenUsageAuditComponent(resolver, clock, validator, IdpSecurityMetricsRecorder.NOOP);
    }

    @AfterEach
    void close() {
        validator.close();
    }

    @Test
    void platformOwnedResourceConfirmsTenantAuditWithoutATenantCopyOfItsManagementClient() {
        var confirmed = producer.appendStrict(event());

        assertThat(confirmed.outcome()).isEqualTo("STORED");
        assertThat(confirmed.sourceClientId()).isEqualTo(OWNER_CLIENT_ID);
        assertThat(confirmed.sourceIssuer()).isEqualTo(ISSUER.toASCIIString());
        assertThat(confirmed.resource()).isEqualTo(RESOURCE.toASCIIString());
        verify(clients).findById(platform, 31L);
        verify(clients, never()).findByClientId(eq(tenant), anyString());
        verify(clients, never()).findById(eq(tenant), anyLong());
        verify(audits).append(tenant, 31L, ISSUER.toASCIIString(), RESOURCE.toASCIIString(), event());
    }

    @Test
    void sameNamedTenantClientCannotReplaceTheRegisteredPlatformOwner() {
        when(clients.findByClientId(tenant, OWNER_CLIENT_ID)).thenReturn(Optional.of(owner().setId(91L)));

        assertThat(producer.appendStrict(event()).sourceClientId()).isEqualTo(OWNER_CLIENT_ID);

        verify(audits).append(tenant, 31L, ISSUER.toASCIIString(), RESOURCE.toASCIIString(), event());
        verify(clients, never()).findByClientId(eq(tenant), anyString());
    }

    @Test
    void missingInactiveOrMismatchedOwnerNeverReachesAuditIntake() {
        when(clients.findById(platform, 31L)).thenReturn(Optional.empty());
        assertUnavailable();
        for (var invalid : List.of(owner().setStatus(OAuthClient.Status.DISABLED), owner().setId(32L),
                owner().setClientId("replacement-owner"), owner().setPurpose(OAuthClientPurposeEnum.USER),
                owner().setClientType(OAuthClient.ClientType.PUBLIC))) {
            when(clients.findById(platform, 31L)).thenReturn(Optional.of(invalid));
            assertUnavailable();
        }
        verifyNoInteractions(audits);
    }

    @Test
    void missingInactiveUnboundOrUnidentifiedResourceNeverSelectsAnOwner() {
        when(resources.findByResourceUri(platform, RESOURCE)).thenReturn(Optional.empty());
        assertUnavailable();
        for (var invalid : List.of(resource().setStatus(ResourceServerStatus.DISABLED),
                resource().setResourceUri(URI.create("https://api.example/other")), resource().setManagementClientPk(null))) {
            when(resources.findByResourceUri(platform, RESOURCE)).thenReturn(Optional.of(invalid));
            assertUnavailable();
        }
        verifyNoInteractions(clients, audits);
    }

    @Test
    void issuerAndResourceChecksAreRetainedBeforeLocalIntake() {
        var wrongResource = new TokenUsageAuditEvent("wrong-resource", 1, ISSUER, "https://api.example/other",
                null, null, null, "SUCCESS", "JWT_ACCEPTED", NOW, null);
        assertThatThrownBy(() -> producer.appendStrict(wrongResource)).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
        var untrusted = new TokenUsageAuditEvent("untrusted-issuer", 1, URI.create("https://idp.example/tenants/1002"),
                RESOURCE.toASCIIString(), null, null, null, "SUCCESS", "JWT_ACCEPTED", NOW, null);
        assertThatThrownBy(() -> producer.appendStrict(untrusted)).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
        verifyNoInteractions(resources, clients, audits);
    }

    @Test
    void strictHandoffStillRequiresMatchingStoredSqlReceiptAndDoesNotRetryIntake() {
        when(audits.append(any(), anyLong(), anyString(), anyString(), any())).thenReturn(receipt(event()).setOutcome("DEAD"));
        assertUnavailable();
        when(audits.append(any(), anyLong(), anyString(), anyString(), any())).thenReturn(receipt(event()).setEventFingerprint("0".repeat(64)));
        assertUnavailable();
        when(audits.append(any(), anyLong(), anyString(), anyString(), any())).thenReturn(null);
        assertUnavailable();
        when(audits.append(any(), anyLong(), anyString(), anyString(), any())).thenThrow(new IllegalStateException("OAUTH_AUDIT_CONFIRMATION_PENDING"));
        assertUnavailable();
        verify(audits, org.mockito.Mockito.times(4)).append(tenant, 31L, ISSUER.toASCIIString(), RESOURCE.toASCIIString(), event());
    }

    private void assertUnavailable() {
        assertThatThrownBy(() -> producer.appendStrict(event())).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
    }

    private static OAuthClientBO owner() {
        return OAuthClientBO.builder().id(31L).clientId(OWNER_CLIENT_ID).purpose(OAuthClientPurposeEnum.SERVICE)
                .clientType(OAuthClient.ClientType.CONFIDENTIAL).status(OAuthClient.Status.ACTIVE).build();
    }

    private static OAuthResourceBO resource() {
        return OAuthResourceBO.builder().id(21L).resourceUri(RESOURCE).managementClientId(OWNER_CLIENT_ID)
                .managementClientPk(31L).status(ResourceServerStatus.ACTIVE).build();
    }

    private static TokenUsageAuditEvent event() {
        return new TokenUsageAuditEvent("native-membership-event", 1, ISSUER, RESOURCE.toASCIIString(),
                null, null, null, "SUCCESS", "JWT_ACCEPTED", NOW, null);
    }

    private static OAuthAuditReceiptBO receipt(TokenUsageAuditEvent event) {
        return OAuthAuditReceiptBO.builder().receiptId(UUID.randomUUID().toString()).eventId(event.eventId())
                .eventFingerprint(TokenUsageAuditFingerprint.of(event)).sourceIssuer(event.issuer().toASCIIString())
                .sourceClientPk(31L).sourceResourceUri(event.resource()).outcome("STORED").confirmedAt(NOW).build();
    }
}
