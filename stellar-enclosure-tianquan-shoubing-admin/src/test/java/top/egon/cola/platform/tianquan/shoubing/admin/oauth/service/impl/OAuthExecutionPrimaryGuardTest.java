package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.DataSourceRoleEnum.*;
import static top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.ModeEnum.*;

class OAuthExecutionPrimaryGuardTest {
    private final DataSource dataSource = mock(DataSource.class);
    private final EgonColaShardingProperties topology = mock(EgonColaShardingProperties.class);
    private final OAuthExecutionPrimaryGuard guard = new OAuthExecutionPrimaryGuard(topology, dataSource);

    @AfterEach
    void clear() {
        if (TransactionSynchronizationManager.hasResource(dataSource)) TransactionSynchronizationManager.unbindResource(dataSource);
        TransactionSynchronizationManager.setActualTransactionActive(false);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(null);
    }

    @Test
    void only_one_primary_in_a_bound_repeatable_read_transaction_is_accepted() throws Exception {
        when(topology.getMode()).thenReturn(SHARDING);
        when(topology.getDataSources()).thenReturn(List.of(source("primary", PRIMARY)));
        Connection connection = mock(Connection.class);
        Statement statement = mock(Statement.class);
        ResultSet result = mock(ResultSet.class);
        ResultSetMetaData columns = mock(ResultSetMetaData.class);
        when(connection.createStatement()).thenReturn(statement);
        when(statement.executeQuery("SELECT pg_is_in_recovery()")).thenReturn(result);
        when(result.getMetaData()).thenReturn(columns);
        when(columns.getColumnCount()).thenReturn(1);
        when(result.next()).thenReturn(true, false);
        when(result.getBoolean(1)).thenReturn(false);
        bind(connection, Connection.TRANSACTION_REPEATABLE_READ);
        assertDoesNotThrow(guard::requirePrimaryTransaction);
        verify(statement).executeQuery("SELECT pg_is_in_recovery()");
    }

    @Test
    void replica_multi_primary_missing_transaction_and_weak_isolation_are_unavailable() {
        when(topology.getMode()).thenReturn(SHARDING);
        when(topology.getDataSources()).thenReturn(List.of(source("primary", PRIMARY)));
        assertUnavailable();
        bind(mock(Connection.class), Connection.TRANSACTION_READ_COMMITTED);
        assertUnavailable();
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(Connection.TRANSACTION_REPEATABLE_READ);
        when(topology.getMode()).thenReturn(SHARDING_READWRITE);
        assertUnavailable();
        when(topology.getMode()).thenReturn(SHARDING);
        when(topology.getDataSources()).thenReturn(List.of(source("primary", PRIMARY), source("other", PRIMARY)));
        assertUnavailable();
        when(topology.getDataSources()).thenReturn(List.of(source("replica", REPLICA)));
        assertUnavailable();
    }

    @Test
    void a_live_standby_cannot_be_misidentified_as_a_primary() throws Exception {
        when(topology.getMode()).thenReturn(SHARDING);
        when(topology.getDataSources()).thenReturn(List.of(source("primary", PRIMARY)));
        Connection connection = mock(Connection.class);
        Statement statement = mock(Statement.class);
        ResultSet result = mock(ResultSet.class);
        ResultSetMetaData columns = mock(ResultSetMetaData.class);
        when(connection.createStatement()).thenReturn(statement);
        when(statement.executeQuery("SELECT pg_is_in_recovery()")).thenReturn(result);
        when(result.getMetaData()).thenReturn(columns);
        when(columns.getColumnCount()).thenReturn(1);
        when(result.next()).thenReturn(true, false);
        when(result.getBoolean(1)).thenReturn(true);
        bind(connection, Connection.TRANSACTION_REPEATABLE_READ);
        assertUnavailable();
    }

    @Test
    void component_uses_the_configured_sharding_properties_and_logical_data_source() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.registerBean("egon.cola.component.mybatis-plus.sharding-top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties",
                    EgonColaShardingProperties.class, () -> topology);
            context.registerBean("dataSource", DataSource.class, () -> dataSource);
            context.register(OAuthExecutionPrimaryGuard.class);
            context.refresh();
            assertNotNull(context.getBean("oauthExecutionPrimaryGuard", OAuthExecutionPrimaryGuard.class));
        }
    }

    private void assertUnavailable() {
        var failure = assertThrows(OAuth2AuthenticationException.class, guard::requirePrimaryTransaction);
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
    }

    private void bind(Connection connection, int isolation) {
        TransactionSynchronizationManager.bindResource(dataSource, new ConnectionHolder(connection));
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionIsolationLevel(isolation);
    }

    private static EgonColaShardingProperties.PhysicalDataSourceProperties source(String name,
            EgonColaShardingProperties.DataSourceRoleEnum role) {
        return new EgonColaShardingProperties.PhysicalDataSourceProperties(name, name, role,
                "org.postgresql.Driver", "jdbc:postgresql://127.0.0.1/example", "fixture", "");
    }
}
