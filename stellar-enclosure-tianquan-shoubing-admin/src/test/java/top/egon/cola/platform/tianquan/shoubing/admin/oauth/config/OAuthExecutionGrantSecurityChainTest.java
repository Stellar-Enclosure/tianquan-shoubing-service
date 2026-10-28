package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.support.TestPropertySourceUtils;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.OAuthExecutionGrantController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.OAuthServiceExecutionGrantController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionGrantService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthServiceExecutionGrantService;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ServiceExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class OAuthExecutionGrantSecurityChainTest {
    @Test void realSecurityChainOwnsAllThreePathsAndRejectsMissingScopes() throws Exception {
        try (var context = new AnnotationConfigWebApplicationContext()) {
            context.setServletContext(new MockServletContext());
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(context, "egon.tianquan-shoubing.execution-grants.enabled=true");
            context.register(Config.class);
            context.refresh();
            var authority = context.getBean(OAuthAuthorityService.class);
            var grants = context.getBean(OAuthExecutionGrantService.class);
            when(authority.authenticateService(eq("service-proof"), anyString())).thenAnswer(invocation -> {
                if (!IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE.equals(invocation.getArgument(1))) {
                    throw new AccessDeniedException("scope denied");
                }
                return caller();
            });
            var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
            String ticket = "{\"ticket\":{\"grantId\":\"9" + "1".repeat(62) + "\",\"ciphertext\":\"ENC:v1:fixture\"}}";
            var resolution = new ExecutionGrantContract.Resolution("9" + "1".repeat(62), "https://idp.example/tenants/101", 101,
                    "subject", "https://api.example/orders", new ExecutionGrantContract.Source("service", "jianshen", "platform", "jianshen", "test"),
                    "TEST", "00000000-0000-0000-0000-000000000123", "c".repeat(64),
                    false, Instant.parse("2026-10-30T00:00:00Z"), Instant.parse("2026-10-30T00:01:00Z"), Set.of("agent:run"));
            when(grants.resolve(any(), any())).thenReturn(resolution);
            for (String path : new String[]{ExecutionGrantContract.ISSUE_PATH, ExecutionGrantContract.RESOLVE_PATH, ExecutionGrantContract.REVOKE_PATH}) {
                mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                        .andExpect(status().isUnauthorized());
                mvc.perform(get(path)).andExpect(status().isMethodNotAllowed());
            }
            mvc.perform(post(ExecutionGrantContract.ISSUE_PATH).header("Authorization", "Bearer service-proof")
                    .contentType(MediaType.APPLICATION_JSON).content("{}")) .andExpect(status().isForbidden());
            mvc.perform(post(ExecutionGrantContract.REVOKE_PATH).header("Authorization", "Bearer service-proof")
                    .contentType(MediaType.APPLICATION_JSON).content("{}")) .andExpect(status().isForbidden());
            mvc.perform(post(ExecutionGrantContract.RESOLVE_PATH).header("Authorization", "Bearer service-proof")
                    .contentType(MediaType.APPLICATION_JSON).content(ticket)).andExpect(status().isOk())
                    .andExpect(header().string("Cache-Control", "no-store"));
            mvc.perform(post("/internal/v1/identity/unlisted")).andExpect(status().isForbidden());
            verify(grants, times(1)).resolve(any(), any());
            verify(grants, never()).issue(any(), any()); verify(grants, never()).revoke(any(), any());
        }
    }

    @Test void realSecurityChainOwnsServiceGrantPathsAndRejectsOtherScopes() throws Exception {
        try (var context = new AnnotationConfigWebApplicationContext()) {
            context.setServletContext(new MockServletContext());
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(context,
                    "egon.tianquan-shoubing.service-execution-grants.enabled=true");
            context.register(Config.class);
            context.refresh();
            var authority = context.getBean(OAuthAuthorityService.class);
            var grants = context.getBean(OAuthServiceExecutionGrantService.class);
            when(authority.authenticateService(eq("service-proof"), anyString())).thenAnswer(invocation -> {
                if (!IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE.equals(invocation.getArgument(1))) {
                    throw new AccessDeniedException("scope denied");
                }
                return caller();
            });
            var mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
            String id = "8" + "1".repeat(62);
            String ticket = "{\"ticket\":{\"grantId\":\"" + id + "\",\"ciphertext\":\"ENC:v1:fixture\"}}";
            var source = new ServiceExecutionGrantContract.Source("service", "agent", "platform", "tianji", "test", "https://api.example/tianji");
            var worker = new ServiceExecutionGrantContract.Source("worker", "process", "platform", "process", "test", "https://api.example/process");
            var resolution = new ServiceExecutionGrantContract.Resolution(id, "https://idp.example/tenants/101", 101,
                    "worker", source.resourceUri(), source, worker, "TEST", "00000000-0000-0000-0000-000000000123", "c".repeat(64),
                    false, Instant.parse("2026-10-30T00:00:00Z"), Instant.parse("2026-10-30T00:01:00Z"), Set.of("agent:run"));
            when(grants.resolve(any(), any())).thenReturn(resolution);
            for (String path : new String[]{ServiceExecutionGrantContract.ISSUE_PATH, ServiceExecutionGrantContract.RESOLVE_PATH,
                    ServiceExecutionGrantContract.REVOKE_PATH}) {
                mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isUnauthorized());
                mvc.perform(get(path)).andExpect(status().isMethodNotAllowed());
            }
            mvc.perform(post(ServiceExecutionGrantContract.ISSUE_PATH).header("Authorization", "Bearer service-proof")
                    .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
            mvc.perform(post(ServiceExecutionGrantContract.REVOKE_PATH).header("Authorization", "Bearer service-proof")
                    .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
            mvc.perform(post(ServiceExecutionGrantContract.RESOLVE_PATH).header("Authorization", "Bearer service-proof")
                    .contentType(MediaType.APPLICATION_JSON).content(ticket)).andExpect(status().isOk())
                    .andExpect(header().string("Cache-Control", "no-store"));
            verify(grants, times(1)).resolve(any(), any());
            verify(grants, never()).issue(any(), any()); verify(grants, never()).revoke(any(), any());
        }
    }

    private static OAuthAuthorityService.Caller caller() {
        var issuer = URI.create("https://idp.example/tenants/101");
        var realm = TrustedRealmBO.builder().issuer(issuer).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
                .storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
        Instant now = Instant.parse("2026-10-23T00:00:00Z");
        var principal = new ServiceIdentityPrincipal("service", "101", "service", "123", URI.create("https://api.example/idp"), 1L,
                Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE),
                "platform", "jianshen", "test", "credential",
                now, now.plusSeconds(300), "jianshen", ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, 12L, URI.create("https://api.example/jianshen"));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @Import({OAuthAuthoritySecurityConfiguration.class, OAuthExecutionGrantController.class, OAuthServiceExecutionGrantController.class})
    static class Config {
        @Bean("oauthAuthorityService") OAuthAuthorityService authority() { return mock(OAuthAuthorityService.class); }
        @Bean("oauthExecutionGrantService") OAuthExecutionGrantService grants() { return mock(OAuthExecutionGrantService.class); }
        @Bean("oauthServiceExecutionGrantService") OAuthServiceExecutionGrantService serviceGrants() { return mock(OAuthServiceExecutionGrantService.class); }
        @Bean("jacksonObjectMapper") ObjectMapper mapper() { return new ObjectMapper().findAndRegisterModules(); }
        @Bean @Order(100) SecurityFilterChain fallback(HttpSecurity http) throws Exception {
            return http.csrf(value -> value.disable()).authorizeHttpRequests(value -> value.anyRequest().denyAll()).build();
        }
    }
}
