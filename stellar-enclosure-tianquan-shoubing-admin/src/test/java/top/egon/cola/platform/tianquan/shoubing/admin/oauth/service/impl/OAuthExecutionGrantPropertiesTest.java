package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class OAuthExecutionGrantPropertiesTest {
    @Test
    void default_is_disabled_and_requires_a_finite_binding_to_enable() {
        new ApplicationContextRunner().withUserConfiguration(Config.class).run(context -> {
            assertFalse(context.getBean(OAuthExecutionGrantProperties.class).enabled());
            assertTrue(context.getBean(OAuthExecutionGrantProperties.class).bindings().isEmpty());
        });
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantProperties(true, List.of()));
    }

    @Test
    void spring_binds_exact_services_scopes_and_lifetime() {
        new ApplicationContextRunner().withUserConfiguration(Config.class).withPropertyValues(
                "egon.tianquan-shoubing.execution-grants.enabled=true",
                "egon.tianquan-shoubing.execution-grants.bindings[0].issuer=https://idp.example/tenants/101",
                "egon.tianquan-shoubing.execution-grants.bindings[0].tenant-id=101",
                "egon.tianquan-shoubing.execution-grants.bindings[0].purpose=TIANJI_AGENT_RUN_EXECUTION",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.client-pk=11",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.client-id=agent-service",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.app-id=agent",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.business-code=platform",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.application-code=tianji",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.environment=test",
                "egon.tianquan-shoubing.execution-grants.bindings[0].source.resource-uri=https://api.example/tianji",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.client-pk=20",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.client-id=rbac-service",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.app-id=rbac",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.business-code=platform",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.application-code=jianshen",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.environment=test",
                "egon.tianquan-shoubing.execution-grants.bindings[0].verifier.resource-uri=https://api.example/jianshen",
                "egon.tianquan-shoubing.execution-grants.bindings[0].required-user-scopes[0]=tianji:agent:start",
                "egon.tianquan-shoubing.execution-grants.bindings[0].session-user-scopes[0]=tianji:agent:read",
                "egon.tianquan-shoubing.execution-grants.bindings[0].max-lifetime=PT30M")
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    var binding = context.getBean(OAuthExecutionGrantProperties.class).bindings().getFirst();
                    assertEquals(101, binding.tenantId());
                    assertEquals(Set.of("tianji:agent:start"), binding.requiredUserScopes());
                    assertEquals(Set.of("tianji:agent:read"), binding.sessionUserScopes());
                    assertEquals(Duration.ofMinutes(30), binding.maxLifetime());
                    assertTrue(binding.fingerprint().matches("[0-9a-f]{64}"));
                });
    }

    @Test
    void configuration_rejects_ambiguous_bindings_and_policy_fingerprint_changes_with_policy() {
        var source = new OAuthExecutionGrantProperties.Service(11, "agent-service", "agent", "platform",
                "tianji", "test", "https://api.example/tianji");
        var verifier = new OAuthExecutionGrantProperties.Service(20, "rbac-service", "rbac", "platform",
                "jianshen", "test", "https://api.example/jianshen");
        var first = new OAuthExecutionGrantProperties.Binding("https://idp.example/tenants/101", 101, source, verifier,
                "TIANJI_AGENT_RUN_EXECUTION", Set.of("a", "b"), Set.of("read"), Duration.ofMinutes(30));
        var same = new OAuthExecutionGrantProperties.Binding("https://idp.example/tenants/101", 101, source, verifier,
                "TIANJI_AGENT_RUN_EXECUTION", Set.of("b", "a"), Set.of("read"), Duration.ofMinutes(30));
        var changed = new OAuthExecutionGrantProperties.Binding("https://idp.example/tenants/101", 101, source, verifier,
                "TIANJI_AGENT_RUN_EXECUTION", Set.of("a"), Set.of("read"), Duration.ofMinutes(30));
        assertEquals(first.fingerprint(), same.fingerprint());
        assertNotEquals(first.fingerprint(), changed.fingerprint());
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantProperties(true, List.of(first, same)));
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantProperties.Binding(
                "https://idp.example/tenants/101", 101, source, source, "TIANJI_AGENT_RUN_EXECUTION",
                Set.of("a"), Set.of(), Duration.ofMinutes(30)));
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantProperties.Binding(
                "https://idp.example/tenants/101", 101, source, verifier, "TIANJI_AGENT_RUN_EXECUTION",
                Set.of("a"), Set.of(), Duration.ofHours(9)));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(OAuthExecutionGrantProperties.class)
    static class Config { }
}
