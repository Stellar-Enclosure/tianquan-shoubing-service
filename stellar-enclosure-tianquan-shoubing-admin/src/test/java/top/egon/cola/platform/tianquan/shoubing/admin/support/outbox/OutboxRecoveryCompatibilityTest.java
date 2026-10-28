package top.egon.cola.platform.tianquan.shoubing.admin.support.outbox;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.session.Configuration;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.outbox.persistence.OutboxShardContext;
import top.egon.cola.component.outbox.persistence.dao.OutboxMessageDAO;

import static org.assertj.core.api.Assertions.assertThat;

class OutboxRecoveryCompatibilityTest {
    @Test void installedRecoveryStatementsParseForPostgresqlAndStayShardScoped() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/outbox/OutboxMessageMapper.xml";
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        OutboxShardContext.withSlot(0, () -> {
            for (String method : List.of("selectExhaustedCandidates", "redriveExhausted")) {
                String sql = configuration.getMappedStatement(OutboxMessageDAO.class.getName() + "." + method)
                        .getBoundSql(Map.of("id", 1L, "version", 2L, "cooldownMillis", 300_000L,
                                "limit", 5, "updateTime", java.time.Instant.EPOCH, "updateUserId", "system:outbox"))
                        .getSql().toLowerCase(java.util.Locale.ROOT);
                assertThat(sql).contains("shard_slot = ?", "outbox_retry_exhausted", "attempt_count >= max_attempts")
                        .doesNotContain("for update", "for share");
                assertThat(parser.parse(sql, false)).isNotNull();
            }
            return null;
        });
    }
}
