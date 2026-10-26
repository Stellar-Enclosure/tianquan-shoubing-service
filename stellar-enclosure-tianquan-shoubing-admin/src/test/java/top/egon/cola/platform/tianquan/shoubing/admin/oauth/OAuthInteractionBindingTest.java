package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthInteractionRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthenticationJwtService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthBrowserInteractionComponent;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthSsoLifecycleService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityFacade;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OAuthInteractionBindingTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final URI ORIGIN = URI.create("https://idp.example");
    private static final URI ISSUER = ORIGIN.resolve("/tenants/101");
    private static final String BROWSER = "browser-fixture-secret";
    private static final String CSRF = "csrf-fixture-secret";
    private static final String ID = "i".repeat(43);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
            .businessTenantId(101L).storagePartitionId(101L).trustVersion(0L).build();
    private final OAuthInteractionRepository rows = mock(OAuthInteractionRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthPayloadCipherComponent cipher = mock(OAuthPayloadCipherComponent.class);
    private final OAuthAuthenticationJwtService authentications = mock(OAuthAuthenticationJwtService.class);
    private final IdentityFacade identities = mock(IdentityFacade.class);
    private OAuthBrowserInteractionComponent interactions;
    private OAuthClientBO client;
    private OAuthInteractionBO row;

    @BeforeEach void prepare() {
        interactions = new OAuthBrowserInteractionComponent(rows, clients, realms, issuers, cipher, authentications,
                identities, mock(OAuthSsoLifecycleService.class), new ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC), ORIGIN);
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(realm);
        client = OAuthClientBO.builder().id(11L).purpose(OAuthClientPurposeEnum.USER).status(OAuthClient.Status.ACTIVE)
                .clientId("web").redirectUris(List.of("https://web.example/callback")).resourceUris(List.of("https://api.example/orders"))
                .allowedScopes(List.of("openid", "orders.read")).build();
        when(clients.findByClientId(realm, "web")).thenReturn(Optional.of(client));
        when(cipher.encrypt(eq(realm), eq("browser-interaction"), anyString(), anyString())).thenReturn("encrypted-fixture");
        when(rows.save(eq(realm), any(), eq(0L))).thenAnswer(i -> i.getArgument(1));
        row = OAuthInteractionBO.builder().interactionId(ID).purpose("AUTHORIZATION").state("PENDING")
                .browserBindingDigest(Digests.sha256Hex(BROWSER)).csrfDigest(Digests.sha256Hex(CSRF)).expiresAt(NOW.plusSeconds(300)).build();
        when(rows.findByInteractionId(realm, ID)).thenAnswer(i -> Optional.of(row));
    }

    @Test void untrustedRedirectAndResourceAreRejectedBeforeAnyInteractionWrite() {
        var redirect = authorize(); redirect.setParameter("redirect_uri", "https://attacker.example/callback");
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(redirect, new MockHttpServletResponse()));
        var target = authorize(); target.setParameter("resource", "https://api.example/other");
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(target, new MockHttpServletResponse()));
        verifyNoInteractions(rows, authentications);
    }

    @Test void invalidPkceDuplicateFieldsAndMissingStateCannotCreateARecord() {
        var plain = authorize(); plain.setParameter("code_challenge_method", "plain");
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(plain, new MockHttpServletResponse()));
        var duplicate = authorize(); duplicate.setParameter("client_id", "web", "other");
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(duplicate, new MockHttpServletResponse()));
        var state = authorize(); state.removeParameter("state");
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(state, new MockHttpServletResponse()));
        verifyNoInteractions(rows, authentications);
    }

    @Test void browserClientBindingIsRequiredAndFrozenInTheSqlInteraction() {
        client.setBrowserBound(true);
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(authorize(), new MockHttpServletResponse()));
        var request = authorize(); request.setParameter("browser_binding", "f".repeat(64));
        var response = new MockHttpServletResponse(); interactions.saveRequest(request, response);
        var saved = org.mockito.ArgumentCaptor.forClass(OAuthInteractionBO.class);
        verify(rows).save(eq(realm), saved.capture(), eq(0L));
        assertEquals("f".repeat(64), saved.getValue().getClientBrowserBindingDigest());
        assertEquals(NOW.plusSeconds(300), saved.getValue().getExpiresAt());
        assertEquals("encrypted-fixture", saved.getValue().getRequestCiphertext());
        assertTrue(response.getHeaders("Set-Cookie").stream().allMatch(value -> value.contains("Secure") && value.contains("HttpOnly") && value.contains("SameSite=Lax")));
        assertNull(request.getSession(false));
    }

    @Test void nonBrowserClientCannotChooseAClientBrowserBinding() {
        var request = authorize(); request.setParameter("browser_binding", "f".repeat(64));
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.saveRequest(request, new MockHttpServletResponse()));
        verifyNoInteractions(rows);
    }

    @Test void anotherBrowserAndChangedCsrfCannotResumeThePendingInteraction() {
        var wrongBrowser = current("other-browser", CSRF);
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.require(wrongBrowser, false));
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.require(current(BROWSER, "other-csrf"), false));
        assertSame(row, interactions.require(current(BROWSER, CSRF), false));
        verifyNoInteractions(authentications, identities);
    }

    @Test void expiredConsumedAndCancelledInteractionsCannotBeReplayed() {
        for (String terminal : List.of("CONSUMED", "CANCELLED", "CLOSED", "EXPIRED")) {
            row.setState(terminal);
            assertThrows(OAuth2AuthenticationException.class, () -> interactions.require(current(BROWSER, CSRF), false));
        }
        row.setState("PENDING").setExpiresAt(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.require(current(BROWSER, CSRF), false));
        verifyNoInteractions(authentications, identities);
    }

    @Test void userInfoAndTokenFailuresDoNotCreateBrowserInteractions() {
        interactions.saveRequest(new MockHttpServletRequest("GET", "/tenants/101/userinfo"), new MockHttpServletResponse());
        interactions.saveRequest(new MockHttpServletRequest("POST", "/tenants/101/oauth2/token"), new MockHttpServletResponse());
        verifyNoInteractions(issuers, rows, clients, authentications);
    }

    @Test void duplicateBrowserCookieIsRejectedInsteadOfSelectingOne() {
        var request = current(BROWSER, CSRF);
        request.setCookies(new Cookie("__Host-idp-binding", BROWSER), new Cookie("__Host-idp-binding", "other"));
        assertThrows(OAuth2AuthenticationException.class, () -> interactions.bindingDigest(request));
    }

    private MockHttpServletRequest authorize() {
        var request = new MockHttpServletRequest("GET", "/tenants/101/oauth2/authorize");
        request.setParameter("client_id", "web"); request.setParameter("response_type", "code");
        request.setParameter("redirect_uri", "https://web.example/callback"); request.setParameter("resource", "https://api.example/orders");
        request.setParameter("scope", "openid orders.read"); request.setParameter("state", "s".repeat(32)); request.setParameter("nonce", "n".repeat(32));
        request.setParameter("code_challenge_method", "S256"); request.setParameter("code_challenge", "c".repeat(43));
        return request;
    }
    private MockHttpServletRequest current(String binding, String csrf) {
        var request = new MockHttpServletRequest("GET", "/tenants/101/login");
        request.setCookies(new Cookie("__Host-idp-binding", binding), new Cookie(OAuthBrowserInteractionComponent.name("csrf", realm), csrf),
                new Cookie(OAuthBrowserInteractionComponent.name("interaction", realm), ID));
        return request;
    }
}
