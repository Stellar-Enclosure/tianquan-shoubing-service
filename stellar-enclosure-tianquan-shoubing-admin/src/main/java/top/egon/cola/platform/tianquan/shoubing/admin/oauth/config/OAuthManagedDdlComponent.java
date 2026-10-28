package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.stereotype.Component;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlManifestBO;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlResult;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlTargetBO;
import top.egon.cola.component.common.mybatis.ddl.EgonColaPostgreDdlRunner;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingTopologyValidator;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingTopologyValidator.TopologyBO;
import top.egon.cola.component.outbox.migration.OutboxStorageTopology;

import javax.sql.DataSource;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

@Component("oauthManagedDdlComponent")
@Slf4j
@RequiredArgsConstructor
public class OAuthManagedDdlComponent {

    private java.util.Set<String> compatibleRouteFingerprints = java.util.Set.of();

    @org.springframework.beans.factory.annotation.Autowired
    void setStorageProperties(@Qualifier("outboxMpStorageProperties")
            top.egon.cola.component.outbox.autoconfigure.OutboxMpStorageProperties properties) {
        this.compatibleRouteFingerprints = java.util.Set.copyOf(properties.getPreviousRouteFingerprints());
    }

    private static final String SCHEMA = "tianquan_oauth";
    private static final String MANIFEST_RESOURCE = "db/egon-mp/repository-manifest.json";

    @Qualifier("egonColaPostgreDdlRunner")
    private final EgonColaPostgreDdlRunner ddlRunner;
    @Qualifier("egonColaShardingTopologyValidator")
    private final EgonColaShardingTopologyValidator topologyValidator;
    private final EgonColaShardingProperties shardingProperties;
    @Qualifier("outboxStateMachineObjectMapper")
    private final ObjectMapper objectMapper;
    @Qualifier("oauthStateSchemaValidator")
    private final OAuthStateSchemaValidator stateSchemaValidator;

    public void initialize(Map<String, DataSource> physicalDataSources, byte[] nativeRules) {
        if (physicalDataSources == null || shardingProperties.getDataSources() == null) {
            throw new IllegalStateException("OAUTH_PRIMARY_DATASOURCE_REQUIRED");
        }
        var primaries = OutboxStorageTopology.primaries(shardingProperties);
        var configured = shardingProperties.getDataSources().stream().map(source -> source.name())
                .collect(java.util.stream.Collectors.toSet());
        if (!physicalDataSources.keySet().equals(configured)
                || primaries.values().stream().anyMatch(primary -> physicalDataSources.get(primary.name()) == null)) {
            throw new IllegalStateException("OAUTH_PRIMARY_DATASOURCE_REQUIRED");
        }

        TopologyBO topology = topologyValidator.validate(shardingProperties, nativeRules);
        EgonColaDdlManifestBO manifest = loadManifest();
        List<EgonColaDdlTargetBO> targets = primaries.values().stream()
                .sorted(java.util.Comparator.comparing(EgonColaShardingProperties.PhysicalDataSourceProperties::name))
                .map(primary -> new EgonColaDdlTargetBO(primary.name(), SCHEMA, EgonColaDdlTargetBO.RoleEnum.MASTER_DATA,
                        new SchemaScopedDataSource(physicalDataSources.get(primary.name()), SCHEMA), manifest, topology.fingerprint(),
                        compatibleRouteFingerprints))
                .toList();
        List<EgonColaDdlResult> results = ddlRunner.run(targets);
        if (results == null || results.size() != targets.size() * manifest.scripts().size()) {
            throw new IllegalStateException("OAUTH_DDL_MANIFEST_INCOMPLETE");
        }
        for (int index = 0; index < results.size(); index++) {
            var result = Objects.requireNonNull(results.get(index), "DDL result");
            var target = targets.get(index / manifest.scripts().size());
            var script = manifest.scripts().get(index % manifest.scripts().size());
            if (!target.alias().equals(result.alias()) || !SCHEMA.equals(result.schema())
                    || !script.version().equals(result.version()) || !script.sha256().equals(result.checksum())
                    || result.status() == null) {
                throw new IllegalStateException("OAUTH_DDL_RESULT_MISMATCH");
            }
        }
        targets.forEach(target -> stateSchemaValidator.validate(target.dataSource()));
        log.info("OAuth managed DDL ready: schema={} primaries={} results={} routeFingerprint={}",
                SCHEMA, targets.size(), results.size(), topology.fingerprint());
    }

    private EgonColaDdlManifestBO loadManifest() {
        try (var input = new ClassPathResource(MANIFEST_RESOURCE).getInputStream()) {
            return objectMapper.readValue(input, EgonColaDdlManifestBO.class);
        } catch (IOException failure) {
            throw new IllegalStateException("OAUTH_DDL_MANIFEST_LOAD_FAILED", failure);
        }
    }

    private static final class SchemaScopedDataSource extends AbstractDataSource {

        private final DataSource delegate;
        private final String schema;

        private SchemaScopedDataSource(DataSource delegate, String schema) {
            this.delegate = Objects.requireNonNull(delegate, "delegate");
            this.schema = Objects.requireNonNull(schema, "schema");
        }

        @Override
        public Connection getConnection() throws SQLException {
            return scope(delegate.getConnection());
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return scope(delegate.getConnection(username, password));
        }

        private Connection scope(Connection connection) throws SQLException {
            String originalSchema;
            try {
                originalSchema = connection.getSchema();
                if (originalSchema == null || originalSchema.isBlank()) {
                    throw new SQLException("OAUTH_DDL_ORIGINAL_SCHEMA_UNKNOWN");
                }
                connection.setSchema(schema);
            } catch (SQLException failure) {
                try {
                    connection.close();
                } catch (SQLException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }

            AtomicBoolean closed = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                    new Class<?>[]{Connection.class}, (proxy, method, arguments) -> {
                        if (method.getDeclaringClass() == Object.class) {
                            return switch (method.getName()) {
                                case "toString" -> "OAuthSchemaScopedConnection[" + schema + ']';
                                case "hashCode" -> System.identityHashCode(proxy);
                                case "equals" -> proxy == arguments[0];
                                default -> throw new UnsupportedOperationException(method.getName());
                            };
                        }
                        if ("close".equals(method.getName()) && method.getParameterCount() == 0) {
                            closeScoped(connection, originalSchema, closed);
                            return null;
                        }
                        if ("unwrap".equals(method.getName()) && method.getParameterCount() == 1) {
                            Class<?> type = (Class<?>) arguments[0];
                            if (type.isInstance(proxy)) {
                                return proxy;
                            }
                            throw new SQLException("OAUTH_DDL_CONNECTION_UNWRAP_UNSUPPORTED");
                        }
                        if ("isWrapperFor".equals(method.getName()) && method.getParameterCount() == 1) {
                            return ((Class<?>) arguments[0]).isInstance(proxy);
                        }
                        try {
                            return method.invoke(connection, arguments);
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
        }

        private static void closeScoped(Connection connection, String originalSchema, AtomicBoolean closed)
                throws SQLException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            SQLException failure = null;
            try {
                if (!connection.isClosed()) {
                    connection.setSchema(originalSchema);
                }
            } catch (SQLException restoreFailure) {
                failure = restoreFailure;
            }
            try {
                connection.close();
            } catch (SQLException closeFailure) {
                if (failure == null) {
                    failure = closeFailure;
                } else {
                    failure.addSuppressed(closeFailure);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }
}
