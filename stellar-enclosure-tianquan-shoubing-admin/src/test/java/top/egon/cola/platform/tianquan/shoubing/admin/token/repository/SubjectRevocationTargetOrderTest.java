package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.time.Instant;
import java.util.UUID;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSecurityStateMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthSecurityStatePO;

import static org.assertj.core.api.Assertions.assertThat;

class SubjectRevocationTargetOrderTest {
    @Test void newerRevisionWinsAndOldOrStaleOwnersCannotChangeItsGeneration() throws Exception {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_security_state (id BIGINT PRIMARY KEY, tenant_id BIGINT, version BIGINT,
                  target_type VARCHAR(16), target_key VARCHAR(128), generation BIGINT, enabled BOOLEAN, revision BIGINT,
                  directory_subject_revision BIGINT, directory_subject_fingerprint CHAR(64), reason_code VARCHAR(128), deleted_at TIMESTAMP,
                  update_user_id VARCHAR(128), update_time TIMESTAMP WITH TIME ZONE)
                """);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (id,tenant_id,version,target_type,target_key,generation,enabled,revision,directory_subject_revision,reason_code) VALUES (?,?,?,?,?,?,?,?,?,?)",
                31L, 7L, 3L, "SUBJECT", "alice", 2L, true, 5L, 4L, "OLD");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/token/OAuthSecurityStateMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthSecurityStateMapper.class);
        var state = new OAuthSecurityStatePO(); state.setId(31L); state.setVersion(4L);
        state.setTargetType(OAuthSecurityTargetEnum.SUBJECT); state.setTargetKey("alice"); state.setGeneration(3L);
        state.setEnabled(false); state.setRevision(6L); state.setDirectorySubjectRevision(9L);
        state.setDirectorySubjectFingerprint("a".repeat(64)); state.setReasonCode("USER_DISABLED");
        state.setUpdateUserId("worker"); state.setUpdateTime(Instant.parse("2026-10-28T00:00:00Z"));
        assertThat(mapper.updateExpectedVersion(7L, state, 3L)).isEqualTo(1);
        assertThat(mapper.fenceSubjectAtLeast(7L, 31L, 4L, "alice", 5L, "b".repeat(64), Instant.parse("2026-10-28T00:00:01Z"), "worker")).isEqualTo(1);
        assertThat(mapper.fenceSubjectAtLeast(7L, 31L, 4L, "alice", 5L, "b".repeat(64), Instant.parse("2026-10-28T00:00:02Z"), "worker")).isZero();
        assertThat(mapper.fenceSubjectAtLeast(7L, 31L, 5L, "alice", 9L, "b".repeat(64), Instant.parse("2026-10-28T00:00:02Z"), "worker")).isZero();
        assertThat(mapper.fenceSubjectAtLeast(7L, 31L, 5L, "alice", 10L, "a".repeat(64), Instant.parse("2026-10-28T00:00:02Z"), "worker")).isZero();
        assertThat(jdbc.queryForObject("SELECT generation FROM tianquan_oauth.oauth_security_state WHERE id=31", Long.class)).isEqualTo(3L);
        assertThat(jdbc.queryForObject("SELECT directory_subject_revision FROM tianquan_oauth.oauth_security_state WHERE id=31", Long.class)).isEqualTo(9L);
    }
}
