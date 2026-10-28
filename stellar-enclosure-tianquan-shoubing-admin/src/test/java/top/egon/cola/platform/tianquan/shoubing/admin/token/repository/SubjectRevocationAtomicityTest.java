package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectRevocationTaskMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository;

import static org.assertj.core.api.Assertions.*;

class SubjectRevocationAtomicityTest {
    @BeforeAll static void ids() { SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5)); }

    @Test void sourceFenceAndTenantTasksCommitOrRollBackTogether() throws Exception {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_identity_user (id BIGINT PRIMARY KEY, tenant_id BIGINT, version BIGINT)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_security_state (id BIGINT PRIMARY KEY, tenant_id BIGINT, version BIGINT, target_type VARCHAR(16), target_key VARCHAR(128), deleted_at TIMESTAMP, update_user_id VARCHAR(128), update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_subject_tenant_history (tenant_id BIGINT, identity_sub VARCHAR(64), identity_tenant_id BIGINT, deleted_at TIMESTAMP)");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_subject_revocation_task (
                  id BIGINT PRIMARY KEY, tenant_id BIGINT, version BIGINT, create_time TIMESTAMP WITH TIME ZONE,
                  create_user_id VARCHAR(128), update_time TIMESTAMP WITH TIME ZONE, update_user_id VARCHAR(128), deleted_at TIMESTAMP,
                  identity_sub VARCHAR(64), target_tenant_id VARCHAR(64), source_revision BIGINT, subject_enabled BOOLEAN,
                  reason_code VARCHAR(128), status VARCHAR(16), next_attempt_at TIMESTAMP WITH TIME ZONE,
                  attempt_count INTEGER, lease_owner VARCHAR(64), lease_until TIMESTAMP WITH TIME ZONE)
                """);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (id,tenant_id,version,target_type,target_key) VALUES (?,?,?,?,?)", 31L, 9000L, 0L, "REALM", "self");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_identity_user (id,tenant_id,version) VALUES (?,?,?)", 41L, 9000L, 0L);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_subject_tenant_history (tenant_id,identity_sub,identity_tenant_id) VALUES (?,?,?)", 9000L, "alice", 7L);
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/token/SubjectRevocationTaskMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(SubjectRevocationTaskMapper.class);
        var repository = new SubjectRevocationTaskRepository(mapper, new IdentityDirectoryContext(9000L, "tenantId"),
                () -> "system:subject-worker", Clock.fixed(Instant.parse("2026-10-28T00:00:00Z"), ZoneOffset.UTC));
        var tx = new TransactionTemplate(new DataSourceTransactionManager(source));
        var platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform")).realmKey("platform")
                .realmType(RealmTypeEnum.PLATFORM).storagePartitionId(9000L).trustVersion(0L).build();
        Instant at = Instant.parse("2026-10-28T00:00:00Z");
        Integer missingTail = tx.execute(status -> mapper.fenceHistoryPage(9000L, 31L, 0L, "alice", 0L, 0L,
                java.util.List.of(), 0, at, "system:subject-worker"));
        Integer substitutedTarget = tx.execute(status -> mapper.fenceHistoryPage(9000L, 31L, 0L, "alice", 0L, 8L,
                java.util.List.of(8L), 1, at, "system:subject-worker"));
        assertThat(missingTail).isZero();
        assertThat(substitutedTarget).isZero();
        assertThatThrownBy(() -> tx.executeWithoutResult(status -> {
            jdbc.update("UPDATE tianquan_oauth.oauth_identity_user SET version=version+1 WHERE id=? AND tenant_id=?", 41L, 9000L);
            repository.enqueueForSubject(platform, OAuthSecurityStateBO.builder().id(31L).version(0L).build(),
                    "alice", 8L, false, "USER_DISABLED");
            throw new IllegalStateException("abort source change");
        })).hasMessage("abort source change");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_subject_revocation_task", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT version FROM tianquan_oauth.oauth_security_state WHERE id=31", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT version FROM tianquan_oauth.oauth_identity_user WHERE id=41", Long.class)).isZero();
        tx.executeWithoutResult(status -> {
            jdbc.update("UPDATE tianquan_oauth.oauth_identity_user SET version=version+1 WHERE id=? AND tenant_id=?", 41L, 9000L);
            repository.enqueueForSubject(platform, OAuthSecurityStateBO.builder().id(31L).version(0L).build(),
                    "alice", 8L, false, "USER_DISABLED");
        });
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_subject_revocation_task", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT version FROM tianquan_oauth.oauth_security_state WHERE id=31", Long.class)).isEqualTo(2L);
        assertThat(jdbc.queryForObject("SELECT version FROM tianquan_oauth.oauth_identity_user WHERE id=41", Long.class)).isEqualTo(1L);
    }
}
