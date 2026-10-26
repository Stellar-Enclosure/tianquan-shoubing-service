package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthAuthorityAuthenticationFilterTest {
    private final OAuthAuthorityService authority = mock(OAuthAuthorityService.class);
    private final OAuthAuthorityAuthenticationFilter filter = new OAuthAuthorityAuthenticationFilter(authority, new ObjectMapper());

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void verifiedServiceGetsRequestOnlyContextAndExplicitIssuerWithoutAnySession() throws Exception {
        var caller = caller();
        when(authority.authenticateService("service-proof", IdentityAuthorityScopes.STATE_RESOLVE)).thenReturn(caller);
        var request = request(); request.addHeader("Authorization", "Bearer service-proof");
        request.setContent("{\"purpose\":\"ACCESS_VALIDATION\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var response = new MockHttpServletResponse(); AtomicBoolean reached = new AtomicBoolean();
        filter.doFilter(request, response, (req, res) -> {
            reached.set(true);
            var token = assertInstanceOf(IdpAuthenticationToken.class, SecurityContextHolder.getContext().getAuthentication());
            assertSame(caller.principal(), token.getPrincipal()); assertEquals(caller.realm().getIssuer(), token.verifiedIssuer());
            assertSame(caller, req.getAttribute(OAuthAuthorityAuthenticationFilter.CALLER_ATTRIBUTE));
            assertEquals("{\"purpose\":\"ACCESS_VALIDATION\"}", new String(req.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        });
        assertTrue(reached.get()); assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNull(request.getAttribute(OAuthAuthorityAuthenticationFilter.CALLER_ATTRIBUTE));
        assertEquals("no-store", response.getHeader("Cache-Control")); assertEquals(0, response.getCookies().length);
    }

    @Test void cookieCannotSubstituteForMissingServiceBearer() throws Exception {
        var request = request(); request.setCookies(new Cookie("access", "untrusted"));
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> fail("Missing service authentication must stop the chain"));
        assertEquals(401, response.getStatus()); verifyNoInteractions(authority);
    }

    @Test void multipleAuthorizationHeadersAreRejectedBeforeVerification() throws Exception {
        var request = request(); request.addHeader("Authorization", "Bearer first"); request.addHeader("Authorization", "Bearer second");
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> fail("Ambiguous credentials must stop the chain"));
        assertEquals(401, response.getStatus()); verifyNoInteractions(authority);
    }

    @Test void userOrInsufficientServiceScopeCannotReachOwnerEndpoint() throws Exception {
        var request = request(); request.addHeader("Authorization", "Bearer user-proof");
        when(authority.authenticateService(anyString(), anyString())).thenThrow(new AccessDeniedException("SERVICE_REQUIRED"));
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> fail("Rejected authority caller"));
        assertEquals(403, response.getStatus());
    }

    @Test void databaseFailureDoesNotFallBackToAnotherStateStore() throws Exception {
        var request = request(); request.addHeader("Authorization", "Bearer service-proof");
        when(authority.authenticateService(anyString(), anyString())).thenThrow(new org.springframework.dao.DataAccessResourceFailureException("database unavailable"));
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> fail("Unavailable authority must fail closed"));
        assertEquals(503, response.getStatus()); assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test void oversizedProofBodyIsBoundedBeforeAuthentication() throws Exception {
        var request = request(); request.addHeader("Authorization", "Bearer service-proof"); request.setContent(new byte[32 * 1024 + 1]);
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> fail("Oversized body must be rejected"));
        assertEquals(413, response.getStatus()); verifyNoInteractions(authority);
    }

    private static MockHttpServletRequest request() {
        return new MockHttpServletRequest("POST", "/internal/v1/identity/security-state:resolve") {
            @Override public HttpSession getSession() { throw new AssertionError("HttpSession is prohibited"); }
            @Override public HttpSession getSession(boolean create) {
                if (create) { throw new AssertionError("HttpSession is prohibited"); }
                return null;
            }
        };
    }

    private static OAuthAuthorityService.Caller caller() {
        URI issuer = URI.create("https://idp.example/tenants/101"), resource = URI.create("https://api.example/orders");
        var realm = TrustedRealmBO.builder().issuer(issuer).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
                .storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
        Instant now = Instant.parse("2026-10-23T00:00:00Z");
        var principal = new ServiceIdentityPrincipal("service", "101", "service", "123", URI.create("https://api.example/idp"), 1L,
                Set.of(IdentityAuthorityScopes.STATE_RESOLVE), "trade", "orders", "test", "credential", now, now.plusSeconds(300),
                "orders", ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, 12L, resource);
    }
}
