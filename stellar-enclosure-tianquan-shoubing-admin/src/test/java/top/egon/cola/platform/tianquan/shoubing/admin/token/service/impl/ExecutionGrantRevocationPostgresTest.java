package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import org.apache.shardingsphere.driver.api.yaml.YamlShardingSphereDataSourceFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.outbox.api.OutboxMessage;
import top.egon.cola.component.outbox.api.OutboxReceipt;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionPrimaryGuard;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthRevocationMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSecurityStateMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthRevocationPO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthSecurityStatePO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;

import javax.sql.DataSource;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Exercises the service's transaction and races with JDBC-backed test repositories. */
@EnabledIfSystemProperty(named = "shoubing.execution.proof.postgres.url", matches = ".+")
class ExecutionGrantRevocationPostgresTest {
    @Test
    void duplicate_revocation_and_outbox_failure_are_atomic_on_one_postgres_primary() throws Exception {
        String url = System.getProperty("shoubing.execution.proof.postgres.url");
        if (url == null || !url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]{1,5}/shoubing_execution_proof_it")) {
            throw new IllegalArgumentException("EXECUTION_PROOF_ISOLATED_POSTGRES_REQUIRED");
        }
        var physical = new DriverManagerDataSource(url, System.getProperty("user.name"), "");
        JdbcTemplate bootstrap = new JdbcTemplate(physical);
        assertEquals("shoubing_execution_proof_it", bootstrap.queryForObject("SELECT current_database()", String.class));
        assertEquals(0, bootstrap.queryForObject("SELECT count(*) FROM pg_namespace WHERE nspname = 'grant_revoke_it'", Integer.class));
        bootstrap.execute("CREATE SCHEMA grant_revoke_it");
        bootstrap.execute("CREATE TABLE grant_revoke_it.realm_row (tenant_id bigint PRIMARY KEY, version bigint NOT NULL)");
        bootstrap.execute("""
                CREATE TABLE grant_revoke_it.state_row (
                  id bigint PRIMARY KEY, tenant_id bigint NOT NULL, version bigint NOT NULL, revision bigint NOT NULL,
                  target_type varchar(16) NOT NULL, target_key varchar(128) NOT NULL, generation bigint NOT NULL,
                  enabled boolean NOT NULL, directory_subject_revision bigint NOT NULL DEFAULT 0,
                  directory_subject_ordered_revision bigint NOT NULL DEFAULT 0, directory_subject_fingerprint varchar(64),
                  reason_code varchar(128) NOT NULL, deleted_at timestamp, update_user_id varchar(128), update_time timestamptz)
                """);
        bootstrap.execute("""
                CREATE TABLE grant_revoke_it.revocation_row (
                  id bigint PRIMARY KEY, tenant_id bigint NOT NULL, target_type varchar(16) NOT NULL, target_key varchar(64) NOT NULL,
                  version bigint NOT NULL, reason varchar(128) NOT NULL, revoked_at timestamptz NOT NULL,
                  expires_at timestamptz, retain_until timestamptz, revision bigint NOT NULL,
                  deleted_at timestamp, update_user_id varchar(128), update_time timestamptz,
                  UNIQUE (tenant_id, target_key))
                """);
        bootstrap.execute("CREATE TABLE grant_revoke_it.audit_row (event_id varchar(64) PRIMARY KEY, event_type varchar(128) NOT NULL)");
        bootstrap.execute("CREATE TABLE grant_revoke_it.outbox_row (idempotency_key varchar(256) PRIMARY KEY)");
        bootstrap.update("INSERT INTO grant_revoke_it.realm_row VALUES (101, 0)");
        bootstrap.update("""
                INSERT INTO grant_revoke_it.state_row
                  (id, tenant_id, version, revision, target_type, target_key, generation, enabled, reason_code)
                VALUES (1, 101, 0, 5, 'REALM', 'self', 1, true, 'INITIALIZED')
                """);
        byte[] yaml = """
                databaseName: egon
                rules:
                  - !SINGLE
                    tables:
                      - oauth_primary.grant_revoke_it.realm_row
                      - oauth_primary.grant_revoke_it.state_row
                      - oauth_primary.grant_revoke_it.revocation_row
                      - oauth_primary.grant_revoke_it.audit_row
                      - oauth_primary.grant_revoke_it.outbox_row
                transaction:
                  defaultType: LOCAL
                props:
                  sql-show: false
                """.getBytes(StandardCharsets.UTF_8);
        DataSource logical = YamlShardingSphereDataSourceFactory.createDataSource(Map.of("oauth_primary", physical), yaml);
        try {
            JdbcTemplate jdbc = new JdbcTemplate(logical);
            var properties = EgonColaShardingProperties.builder().mode(EgonColaShardingProperties.ModeEnum.SHARDING)
                    .configStyle(EgonColaShardingProperties.ConfigStyleEnum.NATIVE)
                    .dataSources(List.of(new EgonColaShardingProperties.PhysicalDataSourceProperties("oauth_primary", "oauth_primary",
                            EgonColaShardingProperties.DataSourceRoleEnum.PRIMARY, "org.postgresql.Driver", url, "fixture", ""))).build();
            var guard = new OAuthExecutionPrimaryGuard(properties, logical);
            var manager = new DataSourceTransactionManager(logical);
            var factory = new SqlSessionFactoryBean();
            factory.setDataSource(logical);
            factory.setMapperLocations(mapper("mapper/token/OAuthSecurityStateMapper.xml"),
                    mapper("mapper/token/OAuthRevocationMapper.xml"));
            var session = new SqlSessionTemplate(factory.getObject());
            var stateMapper = session.getMapper(OAuthSecurityStateMapper.class);
            var revocationMapper = session.getMapper(OAuthRevocationMapper.class);
            var realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101")).realmKey("tenant:101")
                    .realmType(RealmTypeEnum.TENANT).storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
            Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
            AtomicBoolean failOutbox = new AtomicBoolean();
            var service = service(jdbc, manager, guard, stateMapper, revocationMapper, now, failOutbox);
            String first = "9" + "1".repeat(62);
            CountDownLatch start = new CountDownLatch(1);
            try (var pool = Executors.newFixedThreadPool(8)) {
                var results = new ArrayList<java.util.concurrent.Future<?>>();
                for (int i = 0; i < 12; i++) {
                    results.add(pool.submit(() -> {
                        start.await();
                        retryTransaction(manager, () -> service.revokeExecutionGrant(realm, first, now.plusSeconds(7_200)));
                        return null;
                    }));
                }
                start.countDown();
                for (var result : results) result.get(30, TimeUnit.SECONDS);
            } finally {
                start.countDown();
            }
            assertEquals(1, count(jdbc, "revocation_row"));
            assertEquals(1, count(jdbc, "audit_row"));
            assertEquals(1, count(jdbc, "outbox_row"));
            assertEquals(now.plus(Duration.ofHours(8)).plusSeconds(30), jdbc.queryForObject(
                    "SELECT expires_at FROM grant_revoke_it.revocation_row WHERE target_key = ?", Timestamp.class, first).toInstant());

            Instant extendedDeadline = now.plus(Duration.ofDays(2)).plusNanos(123);
            retryTransaction(manager, () -> service.revokeExecutionGrant(realm, first, extendedDeadline));
            retryTransaction(manager, () -> service.revokeExecutionGrant(realm, first, extendedDeadline));
            assertEquals(1, count(jdbc, "revocation_row"));
            assertEquals(2, count(jdbc, "audit_row"));
            assertEquals(2, count(jdbc, "outbox_row"));
            assertEquals(now.plus(Duration.ofDays(2)).plusSeconds(30).plusNanos(1_000), jdbc.queryForObject(
                    "SELECT expires_at FROM grant_revoke_it.revocation_row WHERE target_key = ?", Timestamp.class, first).toInstant());

            String second = "9" + "2".repeat(62);
            long revisionBefore = jdbc.queryForObject("SELECT revision FROM grant_revoke_it.state_row WHERE id = 1", Long.class);
            failOutbox.set(true);
            assertThrows(IllegalStateException.class, () -> transaction(manager).executeWithoutResult(
                    status -> service.revokeExecutionGrant(realm, second, now.plusSeconds(600))));
            assertEquals(1, count(jdbc, "revocation_row"));
            assertEquals(2, count(jdbc, "audit_row"));
            assertEquals(2, count(jdbc, "outbox_row"));
            assertEquals(revisionBefore, jdbc.queryForObject("SELECT revision FROM grant_revoke_it.state_row WHERE id = 1", Long.class));
            failOutbox.set(false);
            retryTransaction(manager, () -> service.revokeExecutionGrant(realm, second, now.plusSeconds(600)));
            assertEquals(2, count(jdbc, "revocation_row"));
            assertEquals(3, count(jdbc, "audit_row"));
            assertEquals(3, count(jdbc, "outbox_row"));
        } finally {
            ((AutoCloseable) logical).close();
        }
    }

    private static TokenRevocationServiceImpl service(JdbcTemplate jdbc, DataSourceTransactionManager manager,
            OAuthExecutionPrimaryGuard guard, OAuthSecurityStateMapper stateMapper,
            OAuthRevocationMapper revocationMapper, Instant now, AtomicBoolean failOutbox) {
        var realms = mock(OAuthRealmRepository.class);
        when(realms.fenceObservedVersion(any())).thenAnswer(call -> jdbc.update(
                "UPDATE grant_revoke_it.realm_row SET version = version + 1 WHERE tenant_id = 101") == 1);
        var states = mock(OAuthSecurityStateRepository.class);
        when(states.findByTarget(any(), eq(OAuthSecurityTargetEnum.REALM), eq("self"))).thenAnswer(call ->
                Optional.of(jdbc.queryForObject("SELECT id, version, revision FROM grant_revoke_it.state_row WHERE tenant_id = 101",
                        (rows, index) -> OAuthSecurityStateBO.builder().id(rows.getLong("id")).version(rows.getLong("version"))
                                .targetType(OAuthSecurityTargetEnum.REALM).targetKey("self").generation(1L)
                                .enabled(true).revision(rows.getLong("revision")).reasonCode("INITIALIZED").build())));
        when(states.advanceRealmIfRevocationAbsent(any(), anyLong(), anyLong(), eq(OAuthSecurityTargetEnum.JTI),
                anyString(), anyLong(), any())).thenAnswer(call -> stateMapper.advanceRealmIfRevocationAbsent(101L,
                call.getArgument(1), call.getArgument(2), OAuthSecurityTargetEnum.JTI, call.getArgument(4),
                call.getArgument(5), call.getArgument(6), "fixture") == 1);
        when(states.save(any(), any(), anyLong())).thenAnswer(call -> {
            OAuthSecurityStateBO value = call.getArgument(1);
            long expected = call.getArgument(2);
            var row = new OAuthSecurityStatePO();
            row.setId(value.getId());
            row.setVersion(value.getVersion());
            row.setTargetType(value.getTargetType()).setTargetKey(value.getTargetKey())
                    .setGeneration(value.getGeneration()).setEnabled(value.isEnabled()).setRevision(value.getRevision())
                    .setDirectorySubjectRevision(value.getDirectorySubjectRevision())
                    .setDirectorySubjectOrderedRevision(value.getDirectorySubjectOrderedRevision())
                    .setDirectorySubjectFingerprint(value.getDirectorySubjectFingerprint()).setReasonCode(value.getReasonCode());
            row.setUpdateUserId("fixture");
            row.setUpdateTime(now);
            if (stateMapper.updateExpectedVersion(101L, row, expected) != 1) throw new OptimisticLockingFailureException("state changed");
            return value;
        });
        AtomicLong ids = new AtomicLong(100);
        var revocations = mock(OAuthRevocationRepository.class);
        when(revocations.findByTarget(any(), eq(OAuthSecurityTargetEnum.JTI), anyString())).thenAnswer(call -> {
            String key = call.getArgument(2);
            return jdbc.query("SELECT * FROM grant_revoke_it.revocation_row WHERE tenant_id = 101 AND target_key = ?",
                    (rows, index) -> OAuthRevocationBO.builder().id(rows.getLong("id")).version(rows.getLong("version"))
                            .targetType(OAuthSecurityTargetEnum.JTI).targetKey(rows.getString("target_key"))
                            .reasonCode(rows.getString("reason")).revokedAt(rows.getTimestamp("revoked_at").toInstant())
                            .expiresAt(rows.getTimestamp("expires_at").toInstant()).retainUntil(rows.getTimestamp("retain_until").toInstant())
                            .revision(rows.getLong("revision")).build(), key).stream().findFirst();
        });
        when(revocations.fenceObservedVersion(any(), any())).thenAnswer(call -> {
            OAuthRevocationBO value = call.getArgument(1);
            return revocationMapper.fenceObservedVersion(101L, value.getId(), OAuthSecurityTargetEnum.JTI,
                    value.getTargetKey(), value.getVersion(), now, "fixture") == 1;
        });
        when(revocations.save(any(), any(), anyLong())).thenAnswer(call -> {
            OAuthRevocationBO value = call.getArgument(1);
            long expected = call.getArgument(2);
            if (value.getId() == null) {
                value.setId(ids.incrementAndGet());
                jdbc.update("""
                        INSERT INTO grant_revoke_it.revocation_row
                          (id, tenant_id, target_type, target_key, version, reason, revoked_at, expires_at, retain_until, revision)
                        VALUES (?, 101, 'JTI', ?, ?, ?, ?, ?, ?, ?)
                        """, value.getId(), value.getTargetKey(), value.getVersion(), value.getReasonCode(),
                        Timestamp.from(value.getRevokedAt()), Timestamp.from(value.getExpiresAt()), Timestamp.from(value.getRetainUntil()), value.getRevision());
            } else {
                var row = new OAuthRevocationPO();
                row.setId(value.getId());
                row.setVersion(value.getVersion());
                row.setTargetType(value.getTargetType()).setTargetKey(value.getTargetKey())
                        .setExpiresAt(value.getExpiresAt()).setRetainUntil(value.getRetainUntil()).setRevision(value.getRevision());
                row.setUpdateUserId("fixture");
                row.setUpdateTime(now);
                if (revocationMapper.updateExpectedVersion(101L, row, expected) != 1) throw new OptimisticLockingFailureException("revocation changed");
            }
            return value;
        });
        var audits = mock(OAuthAuditRepository.class);
        when(audits.findByEventId(any(), anyString())).thenAnswer(call -> jdbc.queryForObject(
                "SELECT count(*) FROM grant_revoke_it.audit_row WHERE event_id = ?", Integer.class, (String) call.getArgument(1)) == 0
                ? Optional.empty() : Optional.of(mock(OAuthAuditBO.class)));
        when(audits.save(any(), any(), anyLong())).thenAnswer(call -> {
            OAuthAuditBO value = call.getArgument(1);
            jdbc.update("INSERT INTO grant_revoke_it.audit_row VALUES (?, ?)", value.getEventId(), value.getEventType());
            return value;
        });
        var outbox = mock(TransactionalOutbox.class);
        when(outbox.enqueue(any())).thenAnswer(call -> {
            OutboxMessage message = call.getArgument(0);
            jdbc.update("INSERT INTO grant_revoke_it.outbox_row VALUES (?)", message.idempotencyKey());
            if (failOutbox.get()) throw new IllegalStateException("fixture outbox failure");
            return new OutboxReceipt(message.messageId(), message.idempotencyKey(), true);
        });
        var service = new TokenRevocationServiceImpl(realms, mock(OAuthClientRepository.class),
                mock(OAuthAuthorizationRepository.class), mock(OAuthTokenRepository.class), states, revocations, audits,
                outbox, mock(OAuthSecurityProjectionComponent.class), mock(OAuthManagementRealmResolver.class),
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(30), manager);
        service.setExecutionPrimary(guard);
        return service;
    }

    private static TransactionTemplate transaction(DataSourceTransactionManager manager) {
        var result = new TransactionTemplate(manager);
        result.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        result.setTimeout(10);
        return result;
    }

    private static ByteArrayResource mapper(String path) throws Exception {
        String xml;
        try (var input = new ClassPathResource(path).getInputStream()) {
            xml = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("tianquan_oauth.oauth_security_state", "grant_revoke_it.state_row")
                    .replace("tianquan_oauth.oauth_revocation", "grant_revoke_it.revocation_row");
        }
        return new ByteArrayResource(xml.getBytes(StandardCharsets.UTF_8), path);
    }

    private static void retryTransaction(DataSourceTransactionManager manager, Runnable operation) {
        for (int attempt = 0; ; attempt++) {
            try {
                transaction(manager).executeWithoutResult(status -> operation.run());
                return;
            } catch (DataAccessException failure) {
                if (attempt >= 19 || !retryable(failure)) throw failure;
            }
        }
    }

    private static boolean retryable(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current instanceof OptimisticLockingFailureException) return true;
            if (current instanceof SQLException sql && ("40001".equals(sql.getSQLState()) || "40P01".equals(sql.getSQLState()))) return true;
        }
        return false;
    }

    private static int count(JdbcTemplate jdbc, String table) {
        if (!List.of("revocation_row", "audit_row", "outbox_row").contains(table)) throw new IllegalArgumentException();
        return jdbc.queryForObject("SELECT count(*) FROM grant_revoke_it." + table, Integer.class);
    }
}
