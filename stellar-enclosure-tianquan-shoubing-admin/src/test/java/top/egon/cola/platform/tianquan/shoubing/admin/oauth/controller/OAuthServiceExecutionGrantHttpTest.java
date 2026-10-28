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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthServiceExecutionGrantService;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ServiceExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class OAuthServiceExecutionGrantHttpTest {
    private static final String SUBJECT = "worker-proof-sentinel";
    private static final String CALLER = "agent-proof-sentinel";
    private static final String ID = "8" + "1".repeat(62);
    private static final String SEALED = "ENC:v1:test:nonce:ciphertext-sentinel";
    private static final String INTENT = "00000000-0000-0000-0000-000000000123";
    private static final Instant DEADLINE = Instant.parse("2026-10-30T00:00:00Z");
    private static final ServiceExecutionGrantContract.Ticket TICKET = new ServiceExecutionGrantContract.Ticket(ID, SEALED);
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final OAuthAuthorityService authority = mock(OAuthAuthorityService.class);
    private final OAuthServiceExecutionGrantService grants = mock(OAuthServiceExecutionGrantService.class);
    private final OAuthAuthorityService.Caller caller = caller();
    private MockMvc mvc;

    @BeforeEach void setUp() {
        when(authority.authenticateService(eq(CALLER), anyString())).thenReturn(caller);
        mvc = MockMvcBuilders.standaloneSetup(new OAuthServiceExecutionGrantController(grants))
                .addFilters(new OAuthAuthorityAuthenticationFilter(authority, mapper)).build();
    }

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void endpointsAreDefaultOff() {
        new ApplicationContextRunner().withUserConfiguration(OAuthServiceExecutionGrantController.class).run(context ->
                assertTrue(context.getBeansOfType(OAuthServiceExecutionGrantController.class).isEmpty()));
        new ApplicationContextRunner().withUserConfiguration(OAuthServiceExecutionGrantController.class)
                .withPropertyValues("egon.tianquan-shoubing.service-execution-grants.enabled=true")
                .withBean("oauthServiceExecutionGrantService", OAuthServiceExecutionGrantService.class, () -> grants)
                .run(context -> assertEquals(1, context.getBeansOfType(OAuthServiceExecutionGrantController.class).size()));
    }

    @Test void eachEndpointAuthenticatesItsDedicatedScopeAndReturnsNoBearer() throws Exception {
        var issue = new ServiceExecutionGrantContract.IssueRequest(SUBJECT, "TIANJI_AGENT_RUN_EXECUTION", INTENT,
                "c".repeat(64), true, DEADLINE);
        var resolve = new ServiceExecutionGrantContract.ResolveRequest(TICKET);
        var revoke = new ServiceExecutionGrantContract.RevokeRequest(TICKET);
        var source = new ServiceExecutionGrantContract.Source("service", "orders", "trade", "orders", "test", "https://api.example/orders");
        var worker = new ServiceExecutionGrantContract.Source("worker", "process", "platform", "process", "test", "https://api.example/process");
        var result = new ServiceExecutionGrantContract.Resolution(ID, caller.realm().getIssuer().toASCIIString(), 101L,
                "worker", source.resourceUri(), source, worker, issue.purpose(), INTENT, issue.bindingSha256(), true,
                DEADLINE.minusSeconds(60), DEADLINE, Set.of("agent:run"));
        when(grants.issue(caller, issue)).thenReturn(new ServiceExecutionGrantContract.Issued(TICKET, DEADLINE.minusSeconds(60)));
        when(grants.resolve(caller, resolve)).thenReturn(result);
        call(ServiceExecutionGrantContract.ISSUE_PATH, mapper.writeValueAsString(issue)).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store")).andExpect(jsonPath("$.ticket.grantId").value(ID));
        call(ServiceExecutionGrantContract.RESOLVE_PATH, mapper.writeValueAsString(resolve)).andExpect(status().isOk())
                .andExpect(jsonPath("$.subjectSource.clientId").value("worker"));
        call(ServiceExecutionGrantContract.REVOKE_PATH, mapper.writeValueAsString(revoke)).andExpect(status().isNoContent());
        verify(authority).authenticateService(CALLER, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE);
        verify(authority).authenticateService(CALLER, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE);
        verify(authority).authenticateService(CALLER, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_REVOKE);
        verify(grants).issue(caller, issue); verify(grants).resolve(caller, resolve); verify(grants).revoke(caller, revoke);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertFalse(issue.toString().contains(SUBJECT)); assertFalse(resolve.toString().contains(SEALED));
        assertFalse(revoke.toString().contains(SEALED)); assertFalse(result.toString().contains("worker"));
    }

    @Test void malformedBodiesAndWrongTicketKindsAreRejectedWithoutEchoingProofs() throws Exception {
        String valid = mapper.writeValueAsString(new ServiceExecutionGrantContract.IssueRequest(SUBJECT,
                "TIANJI_AGENT_RUN_EXECUTION", INTENT, "c".repeat(64), true, DEADLINE));
        for (String bad : new String[]{
                valid.replace("\"serviceToken\":", "\"serviceToken\":\"" + SUBJECT + "\",\"serviceToken\":"),
                valid.replace("\"serviceToken\":", "\"userToken\":"),
                valid.replace("\"serviceToken\":\"" + SUBJECT + "\"", "\"serviceToken\":123"),
                valid.replace("\"sessionRequired\":true", "\"sessionRequired\":\"true\""),
                valid.replace("\"sessionRequired\":true,", ""), valid + " {}", "null"
        }) {
            String response = call(ServiceExecutionGrantContract.ISSUE_PATH, bad).andExpect(status().isBadRequest())
                    .andReturn().getResponse().getContentAsString();
            assertFalse(response.contains(SUBJECT));
        }
        for (String path : new String[]{ServiceExecutionGrantContract.RESOLVE_PATH, ServiceExecutionGrantContract.REVOKE_PATH}) {
            String body = "{\"ticket\":{\"grantId\":\"" + ID + "\",\"ciphertext\":\"" + SEALED + "\"}}";
            call(path, body.replace("\"grantId\":\"" + ID + "\"", "\"grantId\":" + ID)).andExpect(status().isBadRequest());
            call(path, body.replace(ID, "9" + "1".repeat(62))).andExpect(status().isBadRequest());
            call(path, body.substring(0, body.length() - 1) + ",\"serviceToken\":\"" + SUBJECT + "\"}")
                    .andExpect(status().isBadRequest());
        }
        verifyNoInteractions(grants);
    }

    @Test void missingScopeContentTypeAndOversizeFailBeforeGrantHandling() throws Exception {
        mvc.perform(post(ServiceExecutionGrantContract.ISSUE_PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(ServiceExecutionGrantContract.ISSUE_PATH).header("Authorization", "Bearer " + CALLER)
                .contentType(MediaType.TEXT_PLAIN).content("{}")).andExpect(status().isUnsupportedMediaType());
        mvc.perform(post(ServiceExecutionGrantContract.REVOKE_PATH).header("Authorization", "Bearer " + CALLER)
                .contentType(MediaType.APPLICATION_JSON).content(new byte[ExecutionGrantContract.MAX_REQUEST_BYTES + 1]))
                .andExpect(status().isPayloadTooLarge());
        when(authority.authenticateService(CALLER, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE))
                .thenThrow(new AccessDeniedException("missing service scope"));
        call(ServiceExecutionGrantContract.ISSUE_PATH, "{}").andExpect(status().isForbidden());
        verifyNoInteractions(grants);
    }

    @Test void numeric_deadline_preserves_database_microsecond_precision() throws Exception {
        var precise = new ServiceExecutionGrantContract.IssueRequest(SUBJECT, "TIANJI_AGENT_RUN_EXECUTION", INTENT,
                "c".repeat(64), true, Instant.parse("2026-10-30T00:00:00.123456Z"));
        when(grants.issue(caller, precise)).thenReturn(new ServiceExecutionGrantContract.Issued(TICKET, DEADLINE));
        call(ServiceExecutionGrantContract.ISSUE_PATH, mapper.writeValueAsString(precise)).andExpect(status().isOk());
        verify(grants).issue(caller, precise);
    }

    @Test void failures_are_classified_without_returning_sensitive_details() throws Exception {
        String body = mapper.writeValueAsString(new ServiceExecutionGrantContract.ResolveRequest(TICKET));
        when(grants.resolve(eq(caller), any())).thenThrow(
                new OAuth2AuthenticationException(new OAuth2Error("invalid_grant", SUBJECT, null)),
                new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", SUBJECT, null)),
                new DataAccessResourceFailureException(SUBJECT), new IllegalStateException(SUBJECT));
        for (int expected : new int[]{403, 503, 503, 503}) {
            var response = call(ServiceExecutionGrantContract.RESOLVE_PATH, body).andReturn().getResponse();
            assertEquals(expected, response.getStatus());
            assertFalse(response.getContentAsString().contains(SUBJECT));
            assertFalse(response.getContentAsString().contains(SEALED));
            assertEquals("no-store", response.getHeader("Cache-Control"));
        }
    }

    private org.springframework.test.web.servlet.ResultActions call(String path, String body) throws Exception {
        return mvc.perform(post(path).header("Authorization", "Bearer " + CALLER).contentType(MediaType.APPLICATION_JSON)
                .content(body.getBytes(StandardCharsets.UTF_8)));
    }

    private static OAuthAuthorityService.Caller caller() {
        URI issuer = URI.create("https://idp.example/tenants/101"), resource = URI.create("https://api.example/orders");
        var realm = TrustedRealmBO.builder().issuer(issuer).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
                .storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
        Instant now = Instant.parse("2026-10-23T00:00:00Z");
        var principal = new ServiceIdentityPrincipal("service", "101", "service", "123", URI.create("https://api.example/idp"), 1L,
                Set.of(IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE,
                        IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_REVOKE), "trade", "orders", "test", "credential",
                now, now.plusSeconds(300), "orders", ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, 12L, resource);
    }
}
