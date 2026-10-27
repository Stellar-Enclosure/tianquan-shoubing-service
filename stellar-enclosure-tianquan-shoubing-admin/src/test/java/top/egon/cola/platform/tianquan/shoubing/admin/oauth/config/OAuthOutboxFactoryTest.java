package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.select.Select;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuthOutboxFactoryTest {
    @Test
    void initializesBusinessSchemaBeforeTheManagedOutbox() throws Exception {
        var outbox = mock(OutboxManagedDdlInitializer.class);
        var oauth = mock(OAuthManagedDdlComponent.class);
        var factory = new OAuthPersistenceConfiguration().egonColaShardingLogicalDataSourceFactory(oauth, outbox);
        var physical = java.util.Map.of("oauth_primary", mock(javax.sql.DataSource.class));
        byte[] yaml = {1};
        doThrow(new IllegalStateException("OUTBOX_DDL_FAILED")).when(outbox).initialize(physical, yaml);
        assertThatThrownBy(() -> factory.create(physical, yaml)).hasMessage("OUTBOX_DDL_FAILED");
        var order = inOrder(oauth, outbox);
        order.verify(oauth).initialize(physical, yaml);
        order.verify(outbox).initialize(physical, yaml);
    }

    @Test
    void retainsOutboxTechnicalReadAndShardGuards() throws Exception {
        var outbox = mock(OutboxManagedDdlInitializer.class);
        when(outbox.isMultiGroupMode()).thenReturn(true);
        var factory = new OAuthPersistenceConfiguration().egonColaShardingLogicalDataSourceFactory(mock(OAuthManagedDdlComponent.class), outbox);

        assertThat(factory).isInstanceOf(OutboxLogicalDataSourceFactory.class);
        assertThat(factory.permitsPrimaryRead((Select) CCJSqlParserUtil.parse(
                "SELECT script,type,version,checksum,route_fingerprint,tenant_id FROM egon_outbox.ddl_history ORDER BY version")))
                .isTrue();
        assertThat(factory.permitsPrimaryRead((Select) CCJSqlParserUtil.parse(
                "SELECT id FROM orders WHERE id = ? FOR UPDATE"))).isFalse();
        assertThat(factory.enforceSingleWriteGroup()).isTrue();
        assertThatThrownBy(() -> factory.validateLogicalSql("SELECT * FROM egon_cola_outbox_message"))
                .isInstanceOf(java.sql.SQLException.class).hasMessageContaining("OUTBOX_SHARD_SQL_INVALID");
    }
}
