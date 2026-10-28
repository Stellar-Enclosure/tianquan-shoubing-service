package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import org.apache.shardingsphere.driver.api.yaml.YamlShardingSphereDataSourceFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@EnabledIfSystemProperty(named = "shoubing.execution.proof.postgres.url", matches = ".+")
class OAuthExecutionPrimaryGuardPostgresTest {
    @Test
    void logical_single_primary_uses_the_bound_postgres_transaction() throws Exception {
        String url = System.getProperty("shoubing.execution.proof.postgres.url");
        if (url == null || !url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]{1,5}/shoubing_execution_proof_it")) {
            throw new IllegalArgumentException("EXECUTION_PROOF_ISOLATED_POSTGRES_REQUIRED");
        }
        var physical = new DriverManagerDataSource(url, System.getProperty("user.name"), "");
        JdbcTemplate jdbc = new JdbcTemplate(physical);
        assertEquals("shoubing_execution_proof_it", jdbc.queryForObject("SELECT current_database()", String.class));
        assertEquals(0, jdbc.queryForObject("""
                SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'
                """, Integer.class));
        jdbc.execute("CREATE TABLE public.execution_proof_probe (id bigint PRIMARY KEY)");
        byte[] yaml = """
                databaseName: egon
                rules:
                  - !SINGLE
                    tables:
                      - oauth_primary.public.execution_proof_probe
                transaction:
                  defaultType: LOCAL
                props:
                  sql-show: false
                """.getBytes(StandardCharsets.UTF_8);
        DataSource logical = YamlShardingSphereDataSourceFactory.createDataSource(Map.of("oauth_primary", physical), yaml);
        try {
            var properties = EgonColaShardingProperties.builder().mode(EgonColaShardingProperties.ModeEnum.SHARDING)
                    .configStyle(EgonColaShardingProperties.ConfigStyleEnum.NATIVE)
                    .dataSources(List.of(new EgonColaShardingProperties.PhysicalDataSourceProperties("oauth_primary", "oauth_primary",
                            EgonColaShardingProperties.DataSourceRoleEnum.PRIMARY, "org.postgresql.Driver", url, "fixture", ""))).build();
            var guard = new OAuthExecutionPrimaryGuard(properties, logical);
            assertThrows(OAuth2AuthenticationException.class, guard::requirePrimaryTransaction);
            var transaction = new TransactionTemplate(new DataSourceTransactionManager(logical));
            transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
            transaction.executeWithoutResult(status -> guard.requirePrimaryTransaction());
            transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
            assertThrows(OAuth2AuthenticationException.class,
                    () -> transaction.executeWithoutResult(status -> guard.requirePrimaryTransaction()));
            try (var context = new AnnotationConfigApplicationContext()) {
                org.springframework.test.context.support.TestPropertySourceUtils.addInlinedPropertiesToEnvironment(context,
                        "egon.tianquan-shoubing.execution-grants.enabled=true");
                context.register(TransactionConfiguration.class);
                context.registerBean("transactionManager", PlatformTransactionManager.class,
                        () -> new DataSourceTransactionManager(logical));
                context.registerBean("oauthExecutionPrimaryGuard", OAuthExecutionPrimaryGuard.class, () -> guard);
                context.registerBean(OAuthAuthorityService.class, () -> authority(guard));
                context.registerBean(OAuthExecutionGrantService.class, () -> grantService(guard));
                context.refresh();
                OAuthAuthorityService authority = context.getBean(OAuthAuthorityService.class);
                assertTrue(AopUtils.isAopProxy(authority));
                assertThrows(NullPointerException.class,
                        () -> authority.captureExecutionUser(null, java.net.URI.create("https://api.example/orders"), "fixture"));
                OAuthExecutionGrantService grant = context.getBean(OAuthExecutionGrantService.class);
                assertTrue(AopUtils.isAopProxy(grant));
                var request = new OAuthExecutionGrantService.IssueRequest("TIANJI_AGENT_RUN_EXECUTION",
                        "d4c0f428-12ca-487c-a600-303883a19031", "a".repeat(64), false, java.time.Instant.now().plusSeconds(60));
                assertThrows(NullPointerException.class, () -> grant.issue(null, "fixture", request));
            }
        } finally {
            ((AutoCloseable) logical).close();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement(proxyTargetClass = true)
    static class TransactionConfiguration { }

    private static OAuthAuthorityService authority(OAuthExecutionPrimaryGuard guard) {
        var authority = new OAuthAuthorityService(mock(OAuthAuthorityTokenVerifier.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort.class),
                mock(OAuthManagementRealmResolver.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl.OAuthAuditDeliveryService.class),
                new top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties(),
                java.time.Clock.systemUTC());
        authority.setExecutionPrimary(guard);
        return authority;
    }

    private static OAuthExecutionGrantService grantService(OAuthExecutionPrimaryGuard guard) {
        var source = new OAuthExecutionGrantProperties.Service(11, "agent", "agent", "platform", "tianji", "test",
                "https://api.example/tianji");
        var verifier = new OAuthExecutionGrantProperties.Service(20, "rbac", "rbac", "platform", "jianshen", "test",
                "https://api.example/jianshen");
        var binding = new OAuthExecutionGrantProperties.Binding("https://idp.example/tenants/101", 101, source, verifier,
                "TIANJI_AGENT_RUN_EXECUTION", java.util.Set.of("tianji:agent:start"), java.util.Set.of(), java.time.Duration.ofMinutes(30));
        return new OAuthExecutionGrantService(new OAuthExecutionGrantProperties(true, List.of(binding)),
                mock(OAuthAuthorityService.class), guard,
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent.class),
                new com.fasterxml.jackson.databind.ObjectMapper(), java.time.Clock.systemUTC());
    }
}
