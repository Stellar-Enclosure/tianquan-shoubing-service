package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.Objects;

/** Fail closed until multi-primary and replica-safe authority reads have been verified. */
@Component("oauthExecutionPrimaryGuard")
public class OAuthExecutionPrimaryGuard {
    private static final Logger log = LoggerFactory.getLogger(OAuthExecutionPrimaryGuard.class);
    private final EgonColaShardingProperties topology;
    private final DataSource dataSource;
    private final JdbcTemplate jdbc;

    public OAuthExecutionPrimaryGuard(
            @Qualifier("egon.cola.component.mybatis-plus.sharding-top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties")
            EgonColaShardingProperties topology, @Qualifier("dataSource") DataSource dataSource) {
        this.topology = Objects.requireNonNull(topology, "topology");
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.jdbc = new JdbcTemplate(dataSource);
    }

    public void requirePrimaryTransaction() {
        if (topology.getMode() != EgonColaShardingProperties.ModeEnum.SHARDING
                || topology.getDataSources() == null || topology.getDataSources().size() != 1
                || topology.getDataSources().getFirst() == null
                || topology.getDataSources().getFirst().role() != EgonColaShardingProperties.DataSourceRoleEnum.PRIMARY
                || !TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.hasResource(dataSource)
                || (!Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(), Connection.TRANSACTION_REPEATABLE_READ)
                    && !Objects.equals(TransactionSynchronizationManager.getCurrentTransactionIsolationLevel(), Connection.TRANSACTION_SERIALIZABLE))) {
            throw unavailable();
        }
        try {
            if (!Boolean.FALSE.equals(jdbc.queryForObject("SELECT pg_is_in_recovery()", Boolean.class))) {
                throw unavailable();
            }
        } catch (DataAccessException failure) {
            log.warn("Execution identity authority stage=PRIMARY_CHECK outcome=UNAVAILABLE errorType={}",
                    failure.getClass().getSimpleName());
            throw unavailable();
        }
    }

    private static OAuth2AuthenticationException unavailable() {
        return new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", "EXECUTION_AUTHORITY_PRIMARY_REQUIRED", null));
    }
}
