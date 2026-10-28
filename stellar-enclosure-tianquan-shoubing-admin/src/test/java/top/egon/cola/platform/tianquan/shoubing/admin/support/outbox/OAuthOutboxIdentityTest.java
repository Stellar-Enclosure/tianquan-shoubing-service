package top.egon.cola.platform.tianquan.shoubing.admin.support.outbox;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.DataSourceRoleEnum;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.PhysicalDataSourceProperties;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties.TableProperties;
import top.egon.cola.component.common.mybatis.sharding.strategy.EgonColaSingleTableShardingStrategy;
import top.egon.cola.component.common.mybatis.sharding.strategy.EgonColaTechnicalGroupShardingStrategy;
import top.egon.cola.component.outbox.api.OutboxShardIdentity;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class OAuthOutboxIdentityTest {
    @Test
    void derivesStableGloballyScopedIdsAndRejectsMismatches() {
        var sources = List.of(source("a", "group_a", DataSourceRoleEnum.PRIMARY),
                source("ar", "group_a", DataSourceRoleEnum.REPLICA),
                source("b", "group_b", DataSourceRoleEnum.PRIMARY),
                source("br", "group_b", DataSourceRoleEnum.REPLICA));
        var technical = new EgonColaTechnicalGroupShardingStrategy().toRoutingProfile("egon_cola_outbox_message",
                new TableProperties("TECHNICAL_GROUP", "group_a", "shard_slot", null, null,
                        "egon_outbox", List.of("group_a", "group_b")), sources);
        var single = new EgonColaSingleTableShardingStrategy();
        var a = single.toRoutingProfile("oauth_audit", new TableProperties("SINGLE", "group_a", null, null, null), sources);
        var b = single.toRoutingProfile("oauth_grant", new TableProperties("SINGLE", "group_b", null, null, null), sources);
        var identities = new OAuthOutboxIdentity(Map.of("egon_cola_outbox_message", technical,
                "oauth_audit", a, "oauth_grant", b), 9000L);
        var legacy = identities.forTenant("oauth_audit", 9000L);
        var shard = identities.forTenant("oauth_grant", 7L);
        assertThat(legacy.slot()).isZero();
        assertThat(shard.slot()).isNotZero();
        String longId = "a".repeat(64);
        assertThat(legacy.messageId(longId)).isEqualTo(longId);
        String encoded = shard.messageId(longId);
        assertThat(encoded).hasSizeLessThanOrEqualTo(64).startsWith("s1_");
        assertThat(shard.messageId(longId)).isEqualTo(encoded);
        assertThat(shard.idempotencyKey("grant:1")).startsWith("s1_");
        assertThat(OutboxShardIdentity.slotOf(encoded, technical.tenantSlotMap())).isEqualTo(shard.slot());
        assertThatThrownBy(() -> legacy.messageId(encoded)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void grantOutboxPayloadAndIdentifiersBelongToTheSameBusinessGroup() {
        var sources = List.of(source("a", "group_a", DataSourceRoleEnum.PRIMARY),
                source("ar", "group_a", DataSourceRoleEnum.REPLICA),
                source("b", "group_b", DataSourceRoleEnum.PRIMARY),
                source("br", "group_b", DataSourceRoleEnum.REPLICA));
        var technical = new EgonColaTechnicalGroupShardingStrategy().toRoutingProfile("egon_cola_outbox_message",
                new TableProperties("TECHNICAL_GROUP", "group_a", "shard_slot", null, null,
                        "egon_outbox", List.of("group_a", "group_b")), sources);
        var grantProfile = new EgonColaSingleTableShardingStrategy().toRoutingProfile("oauth_grant",
                new TableProperties("SINGLE", "group_b", null, null, null), sources);
        var identities = new OAuthOutboxIdentity(Map.of("egon_cola_outbox_message", technical, "oauth_grant", grantProfile), 9000L);
        var outbox = mock(top.egon.cola.component.outbox.api.TransactionalOutbox.class);
        when(outbox.enqueue(any())).thenAnswer(call -> {
            top.egon.cola.component.outbox.api.OutboxMessage message = call.getArgument(0);
            return new top.egon.cola.component.outbox.api.OutboxReceipt(message.messageId(), message.idempotencyKey(), true);
        });
        var adapter = new top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter(
                outbox, java.time.Clock.systemUTC());
        org.springframework.test.util.ReflectionTestUtils.setField(adapter, "outboxIdentity", identities);
        var realm = top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO.builder()
                .issuer(java.net.URI.create("https://idp.example/tenants/7")).realmKey("tenant:7")
                .realmType(top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum.TENANT)
                .storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();
        var client = top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO.builder().id(4L).clientId("client")
                .clientType(top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient.ClientType.CONFIDENTIAL)
                .purpose(top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum.SERVICE).build();
        var grant = top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO.builder().clientPk(4L)
                .resourceServerId("orders").version(3L)
                .grantType(top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType.CLIENT_CREDENTIALS).build();
        String id = adapter.enqueueServiceGrantProjection(realm, client, grant);
        var captured = org.mockito.ArgumentCaptor.forClass(top.egon.cola.component.outbox.api.OutboxMessage.class);
        verify(outbox).enqueue(captured.capture());
        var message = captured.getValue();
        assertThat(message.messageId()).isEqualTo(id).hasSizeLessThanOrEqualTo(64);
        assertThat(((Map<?, ?>) message.payload()).get("eventId")).isEqualTo(id);
        assertThat(OutboxShardIdentity.slotOf(id, technical.tenantSlotMap())).isEqualTo(identities.forTenant("oauth_grant", 7L).slot());
        assertThat(OutboxShardIdentity.slotOf(message.idempotencyKey(), technical.tenantSlotMap())).isEqualTo(identities.forTenant("oauth_grant", 7L).slot());
    }

    private static PhysicalDataSourceProperties source(String name, String group, DataSourceRoleEnum role) {
        return new PhysicalDataSourceProperties(name, group, role, "org.postgresql.Driver", "jdbc:postgresql://localhost/test", "test", "");
    }
}
