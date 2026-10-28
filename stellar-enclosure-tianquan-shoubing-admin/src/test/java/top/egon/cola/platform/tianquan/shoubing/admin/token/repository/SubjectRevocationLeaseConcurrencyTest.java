package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectRevocationTaskMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO;

import static org.assertj.core.api.Assertions.*;

class SubjectRevocationLeaseConcurrencyTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private SubjectRevocationTaskMapper mapper;
    private TransactionTemplate transaction;
    private JdbcTemplate jdbc;

    @BeforeEach void setUp() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        jdbc = new JdbcTemplate(source);
        jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_subject_revocation_task (
                  id BIGINT PRIMARY KEY, tenant_id BIGINT NOT NULL, version BIGINT NOT NULL,
                  status VARCHAR(16) NOT NULL, next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL,
                  attempt_count INTEGER NOT NULL, lease_owner VARCHAR(64), lease_until TIMESTAMP WITH TIME ZONE,
                  update_user_id VARCHAR(128), update_time TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP)
                """);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_subject_revocation_task (id,tenant_id,version,status,next_attempt_at,attempt_count) VALUES (?,?,?,?,?,?)",
                17L, 9000L, 0L, "PENDING", NOW, 0);
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/token/SubjectRevocationTaskMapper.xml"));
        mapper = new SqlSessionTemplate(factory.getObject()).getMapper(SubjectRevocationTaskMapper.class);
        transaction = new TransactionTemplate(new DataSourceTransactionManager(source));
    }

    @Test void onlyOneConcurrentClaimWinsAndExpiredOwnerCannotComplete() throws Exception {
        var start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var a = workers.submit(() -> { start.await(); return claim("a", 0L, NOW, NOW.plusSeconds(1)); });
            var b = workers.submit(() -> { start.await(); return claim("b", 0L, NOW, NOW.plusSeconds(1)); });
            start.countDown();
            assertThat(List.of(a.get(10, TimeUnit.SECONDS), b.get(10, TimeUnit.SECONDS))).containsExactlyInAnyOrder(0, 1);
        }
        String oldOwner = jdbc.queryForObject("SELECT lease_owner FROM tianquan_oauth.oauth_subject_revocation_task WHERE id=17", String.class);
        assertThat(claim("successor", 1L, NOW.plusSeconds(2), NOW.plusSeconds(60))).isEqualTo(1);
        Integer oldCompletion = transaction.execute(status -> mapper.complete(9000L, task(1L), oldOwner, NOW.plusSeconds(3), "worker"));
        Integer successorCompletion = transaction.execute(status -> mapper.complete(9000L, task(2L), "successor", NOW.plusSeconds(3), "worker"));
        assertThat(oldCompletion).isZero();
        assertThat(successorCompletion).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT status FROM tianquan_oauth.oauth_subject_revocation_task WHERE id=17", String.class)).isEqualTo("DONE");
    }

    @Test void rollbackDoesNotPersistAClaim() {
        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> {
            assertThat(mapper.claim(9000L, task(0L), "worker", NOW.plusSeconds(30), NOW, "worker")).isEqualTo(1);
            throw new IllegalStateException("rollback");
        })).hasMessage("rollback");
        assertThat(jdbc.queryForObject("SELECT status FROM tianquan_oauth.oauth_subject_revocation_task WHERE id=17", String.class)).isEqualTo("PENDING");
    }

    private int claim(String owner, long version, Instant now, Instant until) {
        return transaction.execute(status -> mapper.claim(9000L, task(version), owner, until, now, "worker"));
    }
    private static SubjectRevocationTaskBO task(long version) {
        var task = new SubjectRevocationTaskBO(); task.setId(17L); task.setVersion(version); return task;
    }
}
