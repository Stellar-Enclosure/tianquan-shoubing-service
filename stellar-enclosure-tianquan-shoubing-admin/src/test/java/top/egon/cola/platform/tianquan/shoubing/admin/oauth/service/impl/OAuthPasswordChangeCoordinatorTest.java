package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.PasswordChangeReceiptMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthInteractionRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityFacade;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthPasswordChangeCoordinatorTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmType(RealmTypeEnum.TENANT).realmKey("tenant:7").storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();
    private final OAuthInteractionBO observed = OAuthInteractionBO.builder().id(11L).version(0L).interactionId("interaction")
            .purpose("PASSWORD_CHANGE").restrictedSubject("alice").browserBindingDigest("a".repeat(64))
            .csrfDigest("b".repeat(64)).state("PENDING").build();
    private final OAuthInteractionRepository interactions = mock(OAuthInteractionRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final IdentityFacade identities = mock(IdentityFacade.class);
    private final top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityCredentialRepository credentials =
            mock(top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityCredentialRepository.class);
    private final top.egon.cola.platform.tianquan.shoubing.core.port.PasswordHashPort passwordHashes =
            mock(top.egon.cola.platform.tianquan.shoubing.core.port.PasswordHashPort.class);
    private OAuthPasswordChangeCoordinator coordinator;
    private JdbcTemplate jdbc;

    @BeforeAll static void ids() { SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5)); }

    @BeforeEach void setUp() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_password_change_receipt (
                  id BIGINT PRIMARY KEY, tenant_id BIGINT, version BIGINT, create_time TIMESTAMP WITH TIME ZONE,
                  create_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE, update_user_id VARCHAR, deleted_at TIMESTAMP,
                  operation_key CHAR(64), identity_sub VARCHAR, origin_tenant_id BIGINT, UNIQUE(tenant_id, operation_key))
                """);
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        String mapperXml;
        try (var input = new ClassPathResource("mapper/oauth/PasswordChangeReceiptMapper.xml").getInputStream()) {
            mapperXml = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        assertThat(mapperXml).contains("ON CONFLICT (tenant_id, operation_key) DO NOTHING");
        // H2 accepts DO NOTHING but not PostgreSQL's explicit conflict target.
        factory.setMapperLocations(new ByteArrayResource(mapperXml.replace(
                "ON CONFLICT (tenant_id, operation_key) DO NOTHING", "ON CONFLICT DO NOTHING")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        var receipts = new SqlSessionTemplate(factory.getObject()).getMapper(PasswordChangeReceiptMapper.class);
        coordinator = new OAuthPasswordChangeCoordinator(new DataSourceTransactionManager(source), interactions, realms,
                identities, credentials, passwordHashes, new IdentityDirectoryContext(9000L, "tenantId"), receipts,
                () -> "worker", Clock.fixed(NOW, ZoneOffset.UTC));
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        when(interactions.claimPasswordChange(eq(realm), any(), eq(NOW))).thenReturn(true);
        when(credentials.findByIdentitySub("alice")).thenReturn(java.util.Optional.of(
                new top.egon.cola.platform.tianquan.shoubing.core.identity.PasswordCredential("alice", "encoded", NOW, false,
                        top.egon.cola.platform.tianquan.shoubing.core.identity.PasswordCredential.Status.ACTIVE, 1L)));
        when(passwordHashes.matches(any(char[].class), eq("encoded"))).thenReturn(true);
    }

    @Test void committedDirectoryChangeIsNotRepeatedWhenTargetCompletionMustRetry() {
        when(interactions.consumePasswordChange(eq(realm), any(), eq(NOW))).thenReturn(false, true);
        char[] oldPassword = "old-secret".toCharArray(); char[] newPassword = "new-secret".toCharArray();
        assertThatThrownBy(() -> coordinator.change(realm, observed, oldPassword, newPassword))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_password_change_receipt", Integer.class)).isEqualTo(1);
        assertThat(oldPassword).containsOnly('\0'); assertThat(newPassword).containsOnly('\0');
        coordinator.change(realm, observed, "old-secret".toCharArray(), "new-secret".toCharArray());
        verify(identities, times(1)).changePassword(eq("alice"), any(char[].class), any(char[].class), eq(NOW));
        verify(interactions, times(2)).consumePasswordChange(eq(realm), any(), eq(NOW));
    }

    @Test void failedPasswordChangeRollsBackItsReceipt() {
        doThrow(new IllegalArgumentException("invalid credentials")).when(identities).changePassword(anyString(), any(), any(), any());
        assertThatThrownBy(() -> coordinator.change(realm, observed, "old-secret".toCharArray(), "new-secret".toCharArray()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_password_change_receipt", Integer.class)).isZero();
        verify(interactions, never()).consumePasswordChange(any(), any(), any());
    }

    @Test void concurrentRetriesCommitTheDirectoryChangeOnlyOnce() throws Exception {
        when(interactions.consumePasswordChange(eq(realm), any(), eq(NOW))).thenReturn(true);
        var start = new java.util.concurrent.CountDownLatch(1);
        try (var workers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> { start.await(); coordinator.change(realm, observed,
                    "old-secret".toCharArray(), "new-secret".toCharArray()); return null; });
            var second = workers.submit(() -> { start.await(); coordinator.change(realm, observed,
                    "old-secret".toCharArray(), "new-secret".toCharArray()); return null; });
            start.countDown();
            first.get(10, java.util.concurrent.TimeUnit.SECONDS);
            second.get(10, java.util.concurrent.TimeUnit.SECONDS);
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_password_change_receipt", Integer.class)).isEqualTo(1);
        verify(identities, times(1)).changePassword(eq("alice"), any(char[].class), any(char[].class), eq(NOW));
    }

    @Test void retryWithDifferentOrReplicaStalePasswordDoesNotCompleteTheInteraction() {
        when(interactions.consumePasswordChange(eq(realm), any(), eq(NOW))).thenReturn(false);
        assertThatThrownBy(() -> coordinator.change(realm, observed, "old-secret".toCharArray(), "new-secret".toCharArray()))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        when(passwordHashes.matches(any(char[].class), eq("encoded"))).thenReturn(false);
        assertThatThrownBy(() -> coordinator.change(realm, observed, "old-secret".toCharArray(), "different".toCharArray()))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        verify(interactions, times(1)).consumePasswordChange(eq(realm), any(), eq(NOW));
        verify(identities, times(1)).changePassword(eq("alice"), any(char[].class), any(char[].class), eq(NOW));
    }
}
