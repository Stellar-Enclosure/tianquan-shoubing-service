package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl.OAuthAuditDeliveryService;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationAttributesBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasAuthorizationConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSigningKeyBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenMetadataBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SignedTokenClaimsBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthKeyStatusEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSigningKeyRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.OAuthSecurityVersionBO;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ClientResourceGrant;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceServerStatus;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthExecutionUserProofTest {
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final URI TARGET = URI.create("https://api.example/orders");
    private static final URI AUTHORITY = URI.create("https://api.example/idp");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:101")
            .realmType(RealmTypeEnum.TENANT).storagePartitionId(101L).businessTenantId(101L).trustVersion(2L).build();
    private final TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
            .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(0L).build();
    private final OAuthAuthorityTokenVerifier verifier = mock(OAuthAuthorityTokenVerifier.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthTokenRepository tokens = mock(OAuthTokenRepository.class);
    private final OAuthAuthenticationRepository authentications = mock(OAuthAuthenticationRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final OAuthResourceRepository resources = mock(OAuthResourceRepository.class);
    private final OAuthGrantRepository grants = mock(OAuthGrantRepository.class);
    private final IdentityUserRepository users = mock(IdentityUserRepository.class);
    private final TenantMembershipPort memberships = mock(TenantMembershipPort.class);
    private final OAuthManagementRealmResolver management = mock(OAuthManagementRealmResolver.class);
    private final Clock clock = mock(Clock.class);
    private final AtomicLong subjectGeneration = new AtomicLong(3);
    private final AtomicLong serviceGeneration = new AtomicLong(2);
    private OAuthAuthorityService service;
    private OAuthAuthorizationBO family;
    private OAuthAuthenticationBO authentication;
    private OAuthTokenBO token;
    private OAuthClientBO client;
    private OAuthGrantBO resourceGrant;
    private OAuthResourceBO resource;
    private OAuthClientBO serviceClient;
    private OAuthAuthorizationBO serviceFamily;
    private OAuthTokenBO serviceToken;
    private OAuthGrantBO serviceGrant;

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(NOW);
        var properties = new IdpStarterProperties();
        properties.setResourceUri(AUTHORITY);
        service = new OAuthAuthorityService(verifier, authorizations, clients, tokens, authentications, states,
                revocations, resources, grants, users, memberships, management, mock(OAuthAuditDeliveryService.class),
                properties, clock);
        service.setExecutionPrimary(mock(OAuthExecutionPrimaryGuard.class));
        when(management.platformRealm()).thenReturn(platform);
        client = OAuthClientBO.builder().id(12L).clientId("orders-web").appId("orders")
                .purpose(OAuthClientPurposeEnum.USER).status(OAuthClient.Status.ACTIVE)
                .allowedScopes(List.of("openid", "orders:read")).build();
        family = OAuthAuthorizationBO.builder().id(22L).clientPk(12L).principalName("alice").principalType("USER")
                .audiences(List.of(TARGET.toString())).resourceUri(TARGET.toString())
                .authorizedScopes(List.of("openid", "orders:read")).status("ACTIVE")
                .absoluteExpiresAt(NOW.plusSeconds(28_800)).authenticationJtiDigest(Digests.sha256Hex("900"))
                .refreshGeneration(0L).build();
        var tokenClaims = SignedTokenClaimsBO.builder().issuer(ISSUER).audience(Set.of(TARGET)).subject("alice")
                .scope(Set.of("openid", "orders:read")).tenantId(101L).principalType("USER").jti("302")
                .issuedAt(NOW).notBefore(NOW).expiresAt(NOW.plusSeconds(300)).clientId("orders-web")
                .authorizationId("22").authenticationJti("900").authorizationExpiresAt(NOW.plusSeconds(28_800).getEpochSecond())
                .refreshGeneration("0").clientRegistrationId("12").scopeContext("TENANT").acr("PASSWORD").authTime(NOW)
                .securityVersion(OAuthSecurityVersionBO.builder().realm(1).client(2).subject(3L).build())
                .tokenUse(OAuthTokenTypeEnum.ACCESS).build();
        token = OAuthTokenBO.builder().id(32L).authorizationPk(22L).jti("302").tokenType(OAuthTokenTypeEnum.ACCESS)
                .retainUntil(NOW.plusSeconds(86_400)).metadata(OAuthTokenMetadataBO.builder().claims(tokenClaims).build()).build();
        authentication = OAuthAuthenticationBO.builder().subject("alice").jtiDigest(Digests.sha256Hex("900"))
                .realmGeneration(1L).subjectGeneration(3L).status("ACTIVE").acr("PASSWORD")
                .authenticatedAt(NOW).expiresAt(NOW.plusSeconds(28_800)).build();
        resource = OAuthResourceBO.builder().resourceServerId("orders").resourceUri(TARGET)
                .bizCode("trade").appCode("orders").environment("test").managementClientId("orders-service")
                .version(1).status(ResourceServerStatus.ACTIVE).build();
        resourceGrant = OAuthGrantBO.builder().clientPk(12L).resourceServerId("orders")
                .grantType(ResourceGrantType.USER_DELEGATION).status(ClientResourceGrant.Status.ACTIVE)
                .allowedScopes(List.of("orders:read")).resourceVersion(1L).build();
        when(clients.findById(realm, 12L)).thenReturn(Optional.of(client));
        when(authorizations.findById(realm, 22L)).thenReturn(Optional.of(family));
        when(tokens.findByTokenDigest(realm, Digests.sha256Hex("user-proof"))).thenReturn(Optional.of(token));
        when(authentications.findByJtiDigest(realm, Digests.sha256Hex("900"))).thenReturn(Optional.of(authentication));
        when(resources.findByResourceUri(platform, TARGET)).thenReturn(Optional.of(resource));
        when(grants.findGrant(realm, 12L, "orders", ResourceGrantType.USER_DELEGATION)).thenReturn(Optional.of(resourceGrant));
        serviceClient = OAuthClientBO.builder().id(11L).clientId("orders-service").appId("orders")
                .purpose(OAuthClientPurposeEnum.SERVICE).status(OAuthClient.Status.ACTIVE)
                .allowedScopes(List.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)).build();
        serviceFamily = OAuthAuthorizationBO.builder().id(21L).clientPk(11L).principalName("orders-service")
                .principalType("SERVICE").audiences(List.of(AUTHORITY.toString()))
                .authorizedScopes(List.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE))
                .status("ACTIVE").absoluteExpiresAt(NOW.plusSeconds(300)).build();
        var serviceClaims = SignedTokenClaimsBO.builder().issuer(ISSUER).audience(Set.of(AUTHORITY))
                .subject("orders-service").scope(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)).tenantId(101L)
                .principalType("SERVICE").jti("301").issuedAt(NOW).notBefore(NOW).expiresAt(NOW.plusSeconds(300))
                .clientId("orders-service").authorizationId("21").clientRegistrationId("11").scopeContext("TENANT")
                .sourceBiz("trade").sourceApp("orders").sourceEnv("test").appId("orders").credentialId("credential")
                .resourceVersion(1L).securityVersion(OAuthSecurityVersionBO.builder().realm(1).client(2).build())
                .tokenUse(OAuthTokenTypeEnum.ACCESS).build();
        serviceToken = OAuthTokenBO.builder().id(31L).authorizationPk(21L).jti("301").tokenType(OAuthTokenTypeEnum.ACCESS)
                .retainUntil(NOW.plusSeconds(86_400)).metadata(OAuthTokenMetadataBO.builder().claims(serviceClaims).build()).build();
        serviceGrant = OAuthGrantBO.builder().clientPk(11L).resourceServerId("idp")
                .grantType(ResourceGrantType.CLIENT_CREDENTIALS).status(ClientResourceGrant.Status.ACTIVE)
                .allowedScopes(List.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)).resourceVersion(1L).build();
        when(clients.findById(realm, 11L)).thenReturn(Optional.of(serviceClient));
        when(authorizations.findById(realm, 21L)).thenReturn(Optional.of(serviceFamily));
        when(tokens.findByTokenDigest(realm, "e".repeat(64))).thenReturn(Optional.of(serviceToken));
        when(resources.findBySource(platform, "trade", "orders", "test")).thenReturn(Optional.of(resource));
        when(resources.findByResourceUri(platform, AUTHORITY)).thenReturn(Optional.of(OAuthResourceBO.builder()
                .resourceServerId("idp").resourceUri(AUTHORITY).version(1).status(ResourceServerStatus.ACTIVE).build()));
        when(grants.findGrant(realm, 11L, "idp", ResourceGrantType.CLIENT_CREDENTIALS)).thenReturn(Optional.of(serviceGrant));
        var verifierClient = OAuthClientBO.builder().id(20L).clientId("rbac-service").appId("rbac")
                .purpose(OAuthClientPurposeEnum.SERVICE).status(OAuthClient.Status.ACTIVE)
                .allowedScopes(List.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE)).build();
        var verifierFamily = OAuthAuthorizationBO.builder().id(41L).clientPk(20L).principalName("rbac-service")
                .principalType("SERVICE").audiences(List.of(AUTHORITY.toString()))
                .authorizedScopes(List.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE))
                .status("ACTIVE").absoluteExpiresAt(NOW.plusSeconds(300)).build();
        var verifierClaims = SignedTokenClaimsBO.builder().issuer(ISSUER).audience(Set.of(AUTHORITY))
                .subject("rbac-service").scope(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE)).tenantId(101L)
                .principalType("SERVICE").jti("401").issuedAt(NOW).notBefore(NOW).expiresAt(NOW.plusSeconds(300))
                .clientId("rbac-service").authorizationId("41").clientRegistrationId("20").scopeContext("TENANT")
                .sourceBiz("platform").sourceApp("jianshen").sourceEnv("test").appId("rbac").credentialId("credential")
                .resourceVersion(1L).securityVersion(OAuthSecurityVersionBO.builder().realm(1).client(2).build())
                .tokenUse(OAuthTokenTypeEnum.ACCESS).build();
        var verifierToken = OAuthTokenBO.builder().id(42L).authorizationPk(41L).jti("401").tokenType(OAuthTokenTypeEnum.ACCESS)
                .retainUntil(NOW.plusSeconds(86_400)).metadata(OAuthTokenMetadataBO.builder().claims(verifierClaims).build()).build();
        var verifierResource = OAuthResourceBO.builder().resourceServerId("jianshen")
                .resourceUri(URI.create("https://api.example/jianshen")).bizCode("platform").appCode("jianshen")
                .environment("test").managementClientId("rbac-service").version(1).status(ResourceServerStatus.ACTIVE).build();
        var verifierGrant = OAuthGrantBO.builder().clientPk(20L).resourceServerId("idp")
                .grantType(ResourceGrantType.CLIENT_CREDENTIALS).status(ClientResourceGrant.Status.ACTIVE)
                .allowedScopes(List.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE)).resourceVersion(1L).build();
        when(clients.findById(realm, 20L)).thenReturn(Optional.of(verifierClient));
        when(authorizations.findById(realm, 41L)).thenReturn(Optional.of(verifierFamily));
        when(tokens.findByTokenDigest(realm, "f".repeat(64))).thenReturn(Optional.of(verifierToken));
        when(resources.findBySource(platform, "platform", "jianshen", "test")).thenReturn(Optional.of(verifierResource));
        when(grants.findGrant(realm, 20L, "idp", ResourceGrantType.CLIENT_CREDENTIALS)).thenReturn(Optional.of(verifierGrant));
        when(states.findByTarget(eq(realm), any(), anyString())).thenAnswer(call -> {
            OAuthSecurityTargetEnum type = call.getArgument(1);
            long generation = switch (type) {
                case REALM -> 1;
                case CLIENT -> "11".equals(call.getArgument(2)) ? serviceGeneration.get() : 2;
                case SUBJECT -> subjectGeneration.get();
                default -> -1;
            };
            return generation < 0 ? Optional.empty() : Optional.of(OAuthSecurityStateBO.builder().generation(generation).enabled(true).build());
        });
        when(users.findByIdentitySub("alice")).thenReturn(Optional.of(user(IdentityUserStatus.ACTIVE)));
        when(memberships.resolve("alice", "101")).thenReturn(membership(TenantMembershipPort.MembershipStatus.ACTIVE));
        when(verifier.verify("user-proof", TARGET, null, false)).thenReturn(proof());
    }

    @Test
    void captured_evidence_contains_no_bearer_and_can_be_rechecked_after_access_token_expiry() throws Exception {
        var stored = service.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof");
        assertEquals(Digests.sha256Hex("user-proof"), stored.tokenDigest());
        assertEquals(Digests.sha256Hex("900"), stored.authenticationJtiDigest());
        assertFalse(stored.toString().contains("alice"));
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        String json = mapper.writeValueAsString(stored);
        assertFalse(json.contains("user-proof"));
        assertFalse(json.contains("\"authn_jti\""));
        assertEquals(stored, mapper.readValue(json, StoredUserExecutionProof.class));
        stored.requireRealm(realm);

        when(clock.instant()).thenReturn(NOW.plusSeconds(900));
        var current = service.recheckExecutionUser(realm, stored);
        assertEquals("alice", current.subject());
        assertEquals(101L, current.tenantId());
        assertEquals(Set.of("openid", "orders:read"), current.scopes());
        assertEquals(NOW.plusSeconds(28_800), current.validUntil());
        assertFalse(current.toString().contains("alice"));
        verify(verifier, times(1)).verify("user-proof", TARGET, null, false);
        verify(verifier).requireRecordedKey(realm, "key-1");
    }

    @Test
    void real_authorization_converter_retains_the_token_facts_needed_for_rechecking() {
        var client = RegisteredClient.withId("12").clientId("orders-web")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example/callback").scope("openid").scope("orders:read").build();
        var claims = new java.util.LinkedHashMap<String, Object>();
        claims.put("iss", ISSUER);
        claims.put("aud", List.of(TARGET));
        claims.put("sub", "alice");
        claims.put("scope", "openid orders:read");
        claims.put("tenant_id", "101");
        claims.put("principal_type", "USER");
        claims.put("jti", "302");
        claims.put("iat", NOW);
        claims.put("nbf", NOW);
        claims.put("exp", NOW.plusSeconds(300));
        claims.put("client_id", "orders-web");
        claims.put("authorization_id", "22");
        claims.put("client_registration_id", "12");
        claims.put("scope_context", "TENANT");
        claims.put("security_version", Map.of("realm", 1L, "client", 2L, "subject", 3L));
        claims.put("authn_jti", "900");
        claims.put("acr", "PASSWORD");
        claims.put("auth_time", NOW.getEpochSecond());
        claims.put("authorization_expires_at", NOW.plusSeconds(28_800).getEpochSecond());
        claims.put("authn_expires_at", NOW.plusSeconds(28_800).getEpochSecond());
        claims.put("refresh_generation", "0");
        var access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "synthetic-access-token", NOW,
                NOW.plusSeconds(300), Set.of("openid", "orders:read"));
        var authorization = OAuth2Authorization.withRegisteredClient(client)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).principalName("alice")
                .authorizedScopes(Set.of("openid", "orders:read"))
                .attribute(SasAuthorizationConverter.ATTRIBUTES_ATTRIBUTE, OAuthAuthorizationAttributesBO.builder().build())
                .token(access, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims)).build();
        var mapper = new ObjectMapper().findAndRegisterModules().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        OAuthTokenBO converted = org.mapstruct.factory.Mappers.getMapper(SasAuthorizationConverter.class)
                .toSource(authorization, null, mapper).getTokens().getFirst();
        converted.setAuthorizationPk(22L).setRetainUntil(NOW.plusSeconds(86_400));
        when(tokens.findByTokenDigest(realm, Digests.sha256Hex("user-proof"))).thenReturn(Optional.of(converted));
        var stored = service.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof");
        assertEquals("alice", service.recheckExecutionUser(realm, stored).subject());
    }

    @Test
    void issue_evidence_requires_the_bound_tenant_service_scope_and_target() {
        assertThrows(AccessDeniedException.class, () -> service.captureExecutionUser(caller(Set.of("other")), TARGET, "user-proof"));
        assertThrows(AccessDeniedException.class, () -> service.captureExecutionUser(
                caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), URI.create("https://api.example/other"), "user-proof"));
        assertThrows(AccessDeniedException.class, () -> service.captureExecutionUser(
                caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), URI.create("https://API.example/orders"), "user-proof"));
        var otherRealm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/102")).realmKey("tenant:102")
                .realmType(RealmTypeEnum.TENANT).storagePartitionId(102L).businessTenantId(102L).trustVersion(2L).build();
        var authorized = caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        assertThrows(AccessDeniedException.class, () -> service.captureExecutionUser(
                new OAuthAuthorityService.Caller(authorized.principal(), otherRealm, authorized.clientPk(), TARGET), TARGET, "user-proof"));
        assertThrows(AccessDeniedException.class, () -> service.captureExecutionUser(
                new OAuthAuthorityService.Caller(authorized.principal(), realm, 0, TARGET), TARGET, "user-proof"));
        verifyNoInteractions(verifier);
    }

    @Test
    void legacy_direct_construction_without_the_primary_guard_fails_closed() {
        var unguarded = new OAuthAuthorityService(verifier, authorizations, clients, tokens, authentications, states,
                revocations, resources, grants, users, memberships, management, mock(OAuthAuditDeliveryService.class),
                new IdpStarterProperties(), clock);
        var failure = assertThrows(OAuth2AuthenticationException.class,
                () -> unguarded.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof"));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
        verifyNoInteractions(verifier);
    }

    @Test
    void current_token_family_security_generation_and_authentication_are_rechecked() {
        var stored = service.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof");
        token.setRevokedAt(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        token.setRevokedAt(null);
        family.setStatus("REVOKED");
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        family.setStatus("ACTIVE");
        subjectGeneration.incrementAndGet();
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        subjectGeneration.decrementAndGet();
        authentication.setRevokedAt(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        authentication.setRevokedAt(null).setExpiresAt(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        authentication.setExpiresAt(NOW.plusSeconds(28_800));
        authentication.setStatus("EXPIRED");
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        authentication.setStatus("ACTIVE");
        token.setRetainUntil(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        token.setRetainUntil(NOW.plusSeconds(86_400));
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.KID, "key-1"))
                .thenReturn(Optional.of(mock(OAuthRevocationBO.class)));
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
    }

    @Test
    void account_membership_client_and_resource_scope_changes_revoke_the_recorded_evidence() {
        var stored = service.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof");
        when(users.findByIdentitySub("alice")).thenReturn(Optional.of(user(IdentityUserStatus.DISABLED)));
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        when(users.findByIdentitySub("alice")).thenReturn(Optional.of(user(IdentityUserStatus.ACTIVE)));
        when(memberships.resolve("alice", "101")).thenReturn(membership(TenantMembershipPort.MembershipStatus.DISABLED));
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        when(memberships.resolve("alice", "101")).thenReturn(membership(TenantMembershipPort.MembershipStatus.ACTIVE));
        client.setAllowedScopes(List.of("openid"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        client.setAllowedScopes(List.of("openid", "orders:read"));
        resourceGrant.setStatus(ClientResourceGrant.Status.DISABLED);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        resourceGrant.setStatus(ClientResourceGrant.Status.ACTIVE);
        resource.setStatus(ResourceServerStatus.DISABLED);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
    }

    @Test
    void recorded_evidence_cannot_cross_issuer_tenant_or_issuer_trust_version() {
        var stored = service.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof");
        var changed = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
                .storagePartitionId(101L).businessTenantId(101L).trustVersion(3L).build();
        assertThrows(IllegalArgumentException.class, () -> service.recheckExecutionUser(changed, stored));
    }

    @Test
    void recorded_evidence_cannot_widen_or_rewrite_the_original_token_facts() {
        var stored = service.captureExecutionUser(caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE)), TARGET, "user-proof");
        token.getMetadata().getClaims().setScope(Set.of("openid", "orders:write"));
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        token.getMetadata().getClaims().setScope(Set.of("openid", "orders:read"));
        token.getMetadata().getClaims().getSecurityVersion().setSubject(4L);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
        token.getMetadata().getClaims().getSecurityVersion().setSubject(3L);
        token.getMetadata().setInvalidated(true);
        assertThrows(OAuth2AuthenticationException.class, () -> service.recheckExecutionUser(realm, stored));
    }

    @Test
    void issuing_service_is_rechecked_after_its_access_token_expires() {
        var caller = caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        var user = service.captureExecutionUser(caller, TARGET, "user-proof");
        var envelope = envelope(user);
        assertDoesNotThrow(() -> service.requireExecutionService(caller, envelope.source(), user,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        when(clock.instant()).thenReturn(NOW.plusSeconds(900));
        serviceFamily.setStatus("EXPIRED");
        assertDoesNotThrow(() -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        verify(verifier, atLeastOnce()).requireRecordedKey(realm, "source-key");
    }

    @Test
    void verifier_is_a_separately_authenticated_service_with_its_own_scope_and_facts() {
        var sourceCaller = caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        var user = service.captureExecutionUser(sourceCaller, TARGET, "user-proof");
        var envelope = envelope(user);
        var principal = new ServiceIdentityPrincipal("rbac-service", "101", "rbac-service", "401", AUTHORITY, 1,
                Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE), "platform", "jianshen", "test", "credential",
                NOW.minusSeconds(1), NOW.plusSeconds(300), "rbac", ServiceTokenContext.TENANT);
        var caller = new OAuthAuthorityService.Caller(principal, realm, 20,
                URI.create("https://api.example/jianshen"), 1L, 2L, 41L, "f".repeat(64),
                NOW.plusSeconds(86_400), "verifier-key");
        assertDoesNotThrow(() -> service.requireExecutionService(caller, envelope.verifier(), user,
                IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE));
        assertThrows(AccessDeniedException.class, () -> service.requireExecutionService(caller, envelope.source(), user,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
    }

    @Test
    void issuing_service_revocation_client_rotation_and_scope_changes_invalidate_the_recorded_source() {
        var caller = caller(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        var envelope = envelope(service.captureExecutionUser(caller, TARGET, "user-proof"));
        serviceToken.setRevokedAt(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        serviceToken.setRevokedAt(null);
        serviceGeneration.incrementAndGet();
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        serviceGeneration.decrementAndGet();
        serviceClient.setStatus(OAuthClient.Status.DISABLED);
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        serviceClient.setStatus(OAuthClient.Status.ACTIVE);
        serviceGrant.setStatus(ClientResourceGrant.Status.DISABLED);
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        serviceGrant.setStatus(ClientResourceGrant.Status.ACTIVE);
        serviceToken.getMetadata().getClaims().setAppId("other-app");
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        serviceToken.getMetadata().getClaims().setAppId("orders");
        serviceFamily.setStatus("REVOKED");
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        serviceFamily.setStatus("ACTIVE");
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, "301"))
                .thenReturn(Optional.of(mock(OAuthRevocationBO.class)));
        assertThrows(OAuth2AuthenticationException.class, () -> service.requireRecordedExecutionSource(realm, envelope,
                IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
    }

    @Test
    void recorded_proof_survives_normal_key_rotation_but_not_compromise_or_missing_key() {
        OAuthSigningKeyRepository keys = mock(OAuthSigningKeyRepository.class);
        var key = OAuthSigningKeyBO.builder().kid("key-1").status(OAuthKeyStatusEnum.ACTIVE).build();
        when(keys.findByKid(realm, "key-1")).thenReturn(Optional.of(key));
        var recordedVerifier = new OAuthAuthorityTokenVerifier(mock(TenantIssuerService.class), keys, clock);
        for (OAuthKeyStatusEnum status : List.of(OAuthKeyStatusEnum.ACTIVE, OAuthKeyStatusEnum.VERIFY_ONLY,
                OAuthKeyStatusEnum.RETIRED)) {
            key.setStatus(status);
            assertDoesNotThrow(() -> recordedVerifier.requireRecordedKey(realm, "key-1"));
        }
        for (OAuthKeyStatusEnum status : List.of(OAuthKeyStatusEnum.PUBLISHED, OAuthKeyStatusEnum.COMPROMISED)) {
            key.setStatus(status);
            assertThrows(OAuth2AuthenticationException.class, () -> recordedVerifier.requireRecordedKey(realm, "key-1"));
        }
        when(keys.findByKid(realm, "key-1")).thenReturn(Optional.empty());
        assertThrows(OAuth2AuthenticationException.class, () -> recordedVerifier.requireRecordedKey(realm, "key-1"));
    }

    private OAuthAuthorityService.Caller caller(Set<String> scopes) {
        var principal = new ServiceIdentityPrincipal("orders-service", "101", "orders-service", "301", AUTHORITY,
                1, scopes, "trade", "orders", "test", "credential", NOW.minusSeconds(1), NOW.plusSeconds(600),
                "orders", ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, 11, TARGET, 1L, 2L, 21L,
                "e".repeat(64), NOW.plusSeconds(86_400), "source-key");
    }

    private ExecutionGrantEnvelope envelope(StoredUserExecutionProof user) {
        var source = new ExecutionGrantEnvelope.ServiceBinding(11, "orders-service", "orders", "trade",
                "orders", "test", TARGET.toASCIIString());
        var verifier = new ExecutionGrantEnvelope.ServiceBinding(20, "rbac-service", "rbac", "platform",
                "jianshen", "test", "https://api.example/jianshen");
        String intent = "d4c0f428-12ca-487c-a600-303883a19031";
        String purpose = "TIANJI_AGENT_RUN_EXECUTION";
        return new ExecutionGrantEnvelope(1, OpaqueExecutionGrantCodec.grantId(user, source, purpose, intent),
                source, verifier, 1, 2, 21, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                purpose, intent, "c".repeat(64), "f".repeat(64), false, NOW, NOW.plusSeconds(3_600),
                NOW.plusSeconds(7_200), user);
    }

    private OAuthAuthorityTokenVerifier.VerifiedAccess proof() {
        var claims = new JWTClaimsSet.Builder().issuer(ISSUER.toString()).subject("alice").audience(TARGET.toString())
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300))).jwtID("302")
                .claim("client_registration_id", "12").claim("authorization_id", "22").claim("client_id", "orders-web")
                .claim("principal_type", "USER").claim("tenant_id", "101").claim("scope_context", "TENANT")
                .claim("scope", "openid orders:read").claim("security_version", Map.of("realm", 1, "client", 2, "subject", 3))
                .claim("authn_jti", "900").claim("acr", "PASSWORD").claim("auth_time", NOW.getEpochSecond())
                .claim("refresh_generation", "0").claim("authorization_expires_at", NOW.plusSeconds(28_800).getEpochSecond())
                .claim("authn_expires_at", NOW.plusSeconds(28_800).getEpochSecond()).build();
        return new OAuthAuthorityTokenVerifier.VerifiedAccess(realm, claims, "key-1");
    }

    private static IdentityUser user(IdentityUserStatus status) {
        return new IdentityUser("alice", "alice", "alice", "Alice", status, 0, null, NOW, 0);
    }

    private static TenantMembershipPort.TenantMembership membership(TenantMembershipPort.MembershipStatus status) {
        return new TenantMembershipPort.TenantMembership("alice", "101", "Tenant", status);
    }
}
