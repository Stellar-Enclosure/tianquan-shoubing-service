package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Connection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlTargetBO;
import top.egon.cola.component.common.mybatis.ddl.EgonColaPostgreDdlRunner;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.DataSourceRoleEnum;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.PhysicalDataSourceProperties;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingTopologyValidator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OAuthManagedDdlReplicaTest {
    @Test
    void managedDdlTargetsThePrimaryAndNeverOpensAReplica() throws Exception {
        var runner = mock(EgonColaPostgreDdlRunner.class);
        completeResults(runner);
        var topologyValidator = mock(EgonColaShardingTopologyValidator.class);
        var schemaValidator = mock(OAuthStateSchemaValidator.class);
        var primary = mock(DataSource.class);
        var replica = mock(DataSource.class);
        var connection = mock(Connection.class);
        when(primary.getConnection()).thenReturn(connection);
        when(connection.getSchema()).thenReturn("public");
        var properties = topology();
        byte[] yaml = new byte[0];
        when(topologyValidator.validate(properties, yaml)).thenReturn(new EgonColaShardingTopologyValidator.TopologyBO(
                yaml, Map.of(), Map.of(), Set.of(), "a".repeat(64)));
        var component = new OAuthManagedDdlComponent(runner, topologyValidator, properties,
                new ObjectMapper(), schemaValidator);

        component.initialize(Map.of("oauth_primary", primary, "oauth_replica", replica), yaml);

        @SuppressWarnings("unchecked")
        var targets = org.mockito.ArgumentCaptor.forClass(List.class);
        verify(runner).run(targets.capture());
        var target = (EgonColaDdlTargetBO) targets.getValue().getFirst();
        assertThat(target.alias()).isEqualTo("oauth_primary");
        assertThat(target.role()).isEqualTo(EgonColaDdlTargetBO.RoleEnum.MASTER_DATA);
        verify(schemaValidator).validate(target.dataSource());
        try (var ignored = target.dataSource().getConnection()) {
            verify(connection).setSchema("tianquan_oauth");
        }
        verify(connection).setSchema("public");
        verify(primary).getConnection();
        verifyNoInteractions(replica);
    }

    @Test
    void missingPhysicalReplicaFailsBeforeDdl() {
        var runner = mock(EgonColaPostgreDdlRunner.class);
        completeResults(runner);
        var validator = mock(EgonColaShardingTopologyValidator.class);
        var schema = mock(OAuthStateSchemaValidator.class);
        var properties = topology();
        var component = new OAuthManagedDdlComponent(runner, validator, properties, new ObjectMapper(), schema);
        assertThatThrownBy(() -> component.initialize(Map.of("oauth_primary", mock(DataSource.class)), new byte[0]))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("OAUTH_PRIMARY_DATASOURCE_REQUIRED");
        verifyNoInteractions(runner, validator, schema);
    }

    @Test
    void eachPrimaryIsMigratedAndValidatedWithoutOpeningReplicas() {
        var runner = mock(EgonColaPostgreDdlRunner.class);
        completeResults(runner);
        var validator = mock(EgonColaShardingTopologyValidator.class);
        var schema = mock(OAuthStateSchemaValidator.class);
        var properties = topology();
        properties.setDataSources(List.of(source("oauth_primary", "oauth", DataSourceRoleEnum.PRIMARY),
                source("oauth_replica", "oauth", DataSourceRoleEnum.REPLICA),
                source("other_primary", "other", DataSourceRoleEnum.PRIMARY),
                source("other_replica", "other", DataSourceRoleEnum.REPLICA)));
        byte[] yaml = new byte[0];
        when(validator.validate(properties, yaml)).thenReturn(new EgonColaShardingTopologyValidator.TopologyBO(
                yaml, Map.of(), Map.of(), Set.of(), "b".repeat(64)));
        var first = mock(DataSource.class); var second = mock(DataSource.class);
        var replicaA = mock(DataSource.class); var replicaB = mock(DataSource.class);
        var component = new OAuthManagedDdlComponent(runner, validator, properties, new ObjectMapper(), schema);
        component.setStorageProperties(new top.egon.cola.component.outbox.autoconfigure.OutboxMpStorageProperties()
                .setPreviousRouteFingerprints(List.of("c".repeat(64))));
        component.initialize(Map.of("oauth_primary", first, "oauth_replica", replicaA,
                "other_primary", second, "other_replica", replicaB), yaml);
        @SuppressWarnings("unchecked") var captured = org.mockito.ArgumentCaptor.forClass(List.class);
        verify(runner).run(captured.capture());
        List<EgonColaDdlTargetBO> targets = captured.getValue();
        assertThat(targets).extracting(EgonColaDdlTargetBO::alias).containsExactly("oauth_primary", "other_primary");
        assertThat(targets).allSatisfy(target -> {
            assertThat(target.role()).isEqualTo(EgonColaDdlTargetBO.RoleEnum.MASTER_DATA);
            assertThat(target.compatibleRouteFingerprints()).containsExactly("c".repeat(64));
            verify(schema).validate(target.dataSource());
        });
        verifyNoInteractions(replicaA, replicaB);
    }

    @Test
    void missingMigrationReceiptsFailBeforeSchemaIsDeclaredReady() {
        var runner = mock(EgonColaPostgreDdlRunner.class);
        var validator = mock(EgonColaShardingTopologyValidator.class);
        var schema = mock(OAuthStateSchemaValidator.class);
        var properties = topology(); byte[] yaml = new byte[0];
        when(validator.validate(properties, yaml)).thenReturn(new EgonColaShardingTopologyValidator.TopologyBO(
                yaml, Map.of(), Map.of(), Set.of(), "b".repeat(64)));
        when(runner.run(anyList())).thenReturn(List.of());
        var component = new OAuthManagedDdlComponent(runner, validator, properties, new ObjectMapper(), schema);
        assertThatThrownBy(() -> component.initialize(Map.of("oauth_primary", mock(DataSource.class),
                "oauth_replica", mock(DataSource.class)), yaml)).hasMessageContaining("OAUTH_DDL_MANIFEST_INCOMPLETE");
        verifyNoInteractions(schema);
    }

    private static EgonColaShardingProperties topology() {
        return EgonColaShardingProperties.builder().mode(EgonColaShardingProperties.ModeEnum.SHARDING_READWRITE)
                .configStyle(EgonColaShardingProperties.ConfigStyleEnum.NATIVE).dataSources(List.of(
                        source("oauth_primary", "oauth", DataSourceRoleEnum.PRIMARY),
                        source("oauth_replica", "oauth", DataSourceRoleEnum.REPLICA))).build();
    }

    private static PhysicalDataSourceProperties source(String name, String group, DataSourceRoleEnum role) {
        return new PhysicalDataSourceProperties(name, group, role, "org.postgresql.Driver",
                "jdbc:postgresql://localhost/test", "test", "");
    }

    private static void completeResults(EgonColaPostgreDdlRunner runner) {
        when(runner.run(anyList())).thenAnswer(call -> {
            List<EgonColaDdlTargetBO> targets = call.getArgument(0);
            return targets.stream().flatMap(target -> target.manifest().scripts().stream().map(script ->
                    new top.egon.cola.component.common.mybatis.ddl.EgonColaDdlResult(target.alias(), target.schema(),
                            script.version(), script.sha256(), top.egon.cola.component.common.mybatis.ddl.EgonColaDdlResult.StatusEnum.SKIPPED,
                            java.time.Duration.ZERO))).toList();
        });
    }
}
