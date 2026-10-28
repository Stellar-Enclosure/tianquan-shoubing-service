package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionGrantService;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class OAuthExecutionGrantHttpTest {
    private static final String USER = "user-proof-sentinel";
    private static final String SERVICE = "service-proof-sentinel";
    private static final String ID = "9" + "1".repeat(62);
    private static final String SECRET = "ENC:v1:test:nonce:ciphertext-sentinel";
    private static final String INTENT = "00000000-0000-0000-0000-000000000123";
    private static final Instant DEADLINE = Instant.parse("2026-10-30T00:00:00Z");
    private static final ExecutionGrantContract.Ticket TICKET = new ExecutionGrantContract.Ticket(ID, SECRET);
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final OAuthAuthorityService authority = mock(OAuthAuthorityService.class);
    private final OAuthExecutionGrantService grants = mock(OAuthExecutionGrantService.class);
    private final OAuthAuthorityService.Caller caller = caller();
    private MockMvc mvc;

    @BeforeEach void setup() {
        when(authority.authenticateService(eq(SERVICE), anyString())).thenReturn(caller);
        mvc = MockMvcBuilders.standaloneSetup(new OAuthExecutionGrantController(grants))
                .addFilters(new OAuthAuthorityAuthenticationFilter(authority, mapper)).build();
    }

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void endpointsAreDefaultOff() {
        new ApplicationContextRunner().withUserConfiguration(OAuthExecutionGrantController.class).run(context ->
                assertTrue(context.getBeansOfType(OAuthExecutionGrantController.class).isEmpty()));
        new ApplicationContextRunner().withUserConfiguration(OAuthExecutionGrantController.class)
                .withPropertyValues("egon.tianquan-shoubing.execution-grants.enabled=true")
                .withBean("oauthExecutionGrantService", OAuthExecutionGrantService.class, () -> grants)
                .run(context -> assertEquals(1, context.getBeansOfType(OAuthExecutionGrantController.class).size()));
    }

    @Test void eachEndpointUsesItsOwnServiceScopeAndOnlyTheFilterVerifiedCaller() throws Exception {
        var issue = new ExecutionGrantContract.IssueRequest(USER, "TIANJI_AGENT_RUN_EXECUTION", INTENT,
                "c".repeat(64), true, DEADLINE);
        var resolve = new ExecutionGrantContract.ResolveRequest(TICKET);
        var revoke = new ExecutionGrantContract.RevokeRequest(USER, TICKET);
        var resolution = new ExecutionGrantContract.Resolution(ID, caller.realm().getIssuer().toString(), 101L,
                "subject", "https://api.example/orders", new ExecutionGrantContract.Source("service", "orders", "trade", "orders", "test"),
                issue.purpose(), INTENT, issue.bindingSha256(), true,
                DEADLINE.minusSeconds(60), DEADLINE, Set.of("agent:run"));
        when(grants.issue(caller, issue)).thenReturn(new ExecutionGrantContract.Issued(TICKET, DEADLINE.minusSeconds(60)));
        when(grants.resolve(caller, resolve)).thenReturn(resolution);
        call(ExecutionGrantContract.ISSUE_PATH, mapper.writeValueAsString(issue)).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.ticket.grantId").value(ID));
        call(ExecutionGrantContract.RESOLVE_PATH, mapper.writeValueAsString(resolve)).andExpect(status().isOk())
                .andExpect(jsonPath("$.intentId").value(INTENT));
        call(ExecutionGrantContract.REVOKE_PATH, mapper.writeValueAsString(revoke)).andExpect(status().isNoContent());
        verify(authority).authenticateService(SERVICE, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE);
        verify(authority).authenticateService(SERVICE, IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE);
        verify(authority).authenticateService(SERVICE, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE);
        verify(grants).issue(caller, issue); verify(grants).resolve(caller, resolve); verify(grants).revoke(caller, revoke);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertFalse(issue.toString().contains(USER)); assertFalse(resolve.toString().contains(SECRET));
        assertFalse(revoke.toString().contains(USER)); assertFalse(TICKET.toString().contains(SECRET));
    }

    @Test void malformedBodiesAreRejectedWithoutInvokingGrantServiceOrEchoingProofs() throws Exception {
        String valid = mapper.writeValueAsString(new ExecutionGrantContract.IssueRequest(USER, "TIANJI_AGENT_RUN_EXECUTION",
                INTENT, "c".repeat(64), true, DEADLINE));
        for (String bad : new String[] {
                valid.replace("\"userToken\":", "\"userToken\":\"" + USER + "\",\"userToken\":"),
                valid.replace("\"sessionRequired\":true", "\"sessionRequired\":\"true\""),
                valid.replace("\"userToken\":\"" + USER + "\"", "\"userToken\":12345"),
                valid.replace("\"sessionRequired\":true,", ""),
                valid.replace("\"sessionRequired\":true", "\"sessionRequired\":null"),
                valid.substring(0, valid.length() - 1) + ",\"unexpected\":\"" + USER + "\"}",
                valid + " {}", "null"
        }) {
            String response = call(ExecutionGrantContract.ISSUE_PATH, bad).andExpect(status().isBadRequest())
                    .andReturn().getResponse().getContentAsString();
            assertFalse(response.contains(USER));
        }
        verifyNoInteractions(grants);
    }

    @Test void ticket_identifiers_must_be_json_strings_for_resolve_and_revoke() throws Exception {
        for (var entry : java.util.Map.of(
                ExecutionGrantContract.RESOLVE_PATH, mapper.writeValueAsString(new ExecutionGrantContract.ResolveRequest(TICKET)),
                ExecutionGrantContract.REVOKE_PATH, mapper.writeValueAsString(new ExecutionGrantContract.RevokeRequest(USER, TICKET))).entrySet()) {
            String malformed = entry.getValue().replace("\"grantId\":\"" + ID + "\"", "\"grantId\":" + ID);
            assertNotEquals(entry.getValue(), malformed);
            call(entry.getKey(), malformed).andExpect(status().isBadRequest());
        }
        verifyNoInteractions(grants);
    }

    @Test void missingAuthenticationWrongContentTypeAndOversizeFailBeforeGrantHandling() throws Exception {
        mvc.perform(post(ExecutionGrantContract.ISSUE_PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(ExecutionGrantContract.ISSUE_PATH).header("Authorization", "Bearer " + SERVICE)
                .contentType(MediaType.TEXT_PLAIN).content("{}")) .andExpect(status().isUnsupportedMediaType());
        mvc.perform(post(ExecutionGrantContract.ISSUE_PATH).header("Authorization", "Bearer " + SERVICE)
                .header("Content-Type", "application/json", "text/plain").content("{}"))
                .andExpect(status().isUnsupportedMediaType());
        mvc.perform(post(ExecutionGrantContract.REVOKE_PATH).header("Authorization", "Bearer " + SERVICE)
                .contentType(MediaType.APPLICATION_JSON).content(new byte[ExecutionGrantContract.MAX_REQUEST_BYTES + 1]))
                .andExpect(status().isPayloadTooLarge());
        verifyNoInteractions(authority, grants);
    }

    @Test void callerAttributeCannotReplaceAuthenticationOrVerifiedIssuer() {
        var request = new MockHttpServletRequest();
        request.setAttribute(OAuthAuthorityAuthenticationFilter.CALLER_ATTRIBUTE, caller);
        assertThrows(org.springframework.security.access.AccessDeniedException.class, () -> OAuthAuthorityController.caller(request));
        SecurityContextHolder.getContext().setAuthentication(new IdpAuthenticationToken(caller.principal(), java.util.List.of(),
                URI.create("https://other.example/tenants/101")));
        assertThrows(org.springframework.security.access.AccessDeniedException.class, () -> OAuthAuthorityController.caller(request));
    }

    @Test void serviceFailuresAreClassifiedWithoutReturningSensitiveDetails() throws Exception {
        String body = mapper.writeValueAsString(new ExecutionGrantContract.ResolveRequest(TICKET));
        when(grants.resolve(eq(caller), any())).thenThrow(
                new OAuth2AuthenticationException(new OAuth2Error("invalid_grant", USER, null)),
                new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", USER, null)),
                new DataAccessResourceFailureException(USER), new IllegalStateException(USER));
        for (int expected : new int[]{403, 503, 503, 503}) {
            var response = call(ExecutionGrantContract.RESOLVE_PATH, body).andReturn().getResponse();
            assertEquals(expected, response.getStatus()); assertFalse(response.getContentAsString().contains(USER));
            assertFalse(response.getContentAsString().contains(SECRET)); assertEquals("no-store", response.getHeader("Cache-Control"));
        }
    }

    private org.springframework.test.web.servlet.ResultActions call(String path, String body) throws Exception {
        return mvc.perform(post(path).header("Authorization", "Bearer " + SERVICE).contentType(MediaType.APPLICATION_JSON)
                .content(body.getBytes(StandardCharsets.UTF_8)));
    }

    private static OAuthAuthorityService.Caller caller() {
        URI issuer = URI.create("https://idp.example/tenants/101"), resource = URI.create("https://api.example/orders");
        var realm = TrustedRealmBO.builder().issuer(issuer).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
                .storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
        Instant now = Instant.parse("2026-10-23T00:00:00Z");
        var principal = new ServiceIdentityPrincipal("service", "101", "service", "123", URI.create("https://api.example/idp"), 1L,
                Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE, IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE,
                        IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE), "trade", "orders", "test", "credential",
                now, now.plusSeconds(300), "orders", ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, 12L, resource);
    }
}
