package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSecurityStateMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectDeliveryReceiptMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.converter.OAuthSecurityStateConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.OAuthSecurityStateRepositoryImpl;

import static org.assertj.core.api.Assertions.*;

class OAuthSubjectDeliveryOrderServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmKey("tenant:7").realmType(RealmTypeEnum.TENANT).storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();
    private OAuthSubjectDeliveryOrderService service;
    private TransactionTemplate transaction;
    private JdbcTemplate jdbc;

    @BeforeAll static void ids() { SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5)); }
    @BeforeEach void setup() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_security_state (id BIGINT, tenant_id BIGINT, version BIGINT,
                  create_time TIMESTAMP WITH TIME ZONE, create_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE,
                  update_user_id VARCHAR, deleted_at TIMESTAMP, target_type VARCHAR, target_key VARCHAR, generation BIGINT,
                  enabled BOOLEAN, revision BIGINT, directory_subject_revision BIGINT, directory_subject_ordered_revision BIGINT,
                  directory_subject_fingerprint CHAR(64), reason_code VARCHAR)
                """);
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_subject_delivery_receipt (id BIGINT PRIMARY KEY, tenant_id BIGINT,
                  version BIGINT, create_time TIMESTAMP WITH TIME ZONE, create_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE,
                  update_user_id VARCHAR, deleted_at TIMESTAMP, event_id VARCHAR, identity_sub VARCHAR, source_revision BIGINT,
                  previous_revision BIGINT, payload_fingerprint CHAR(64),
                  UNIQUE(tenant_id,event_id), UNIQUE(tenant_id,identity_sub,source_revision))
                """);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (id,tenant_id,version,target_type,target_key,generation,enabled,revision,directory_subject_revision,directory_subject_ordered_revision,reason_code) VALUES (42,7,3,'SUBJECT','alice',2,TRUE,9,20,20,'TEST')");
        String receiptXml;
        try (var input = new ClassPathResource("mapper/token/SubjectDeliveryReceiptMapper.xml").getInputStream()) {
            receiptXml = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        assertThat(receiptXml).contains("ON CONFLICT (tenant_id, event_id) DO NOTHING");
        // H2 supports DO NOTHING but not PostgreSQL's explicit conflict target.
        var adapted = new ByteArrayResource(receiptXml.replace("ON CONFLICT (tenant_id, event_id) DO NOTHING", "ON CONFLICT DO NOTHING")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/token/OAuthSecurityStateMapper.xml"), adapted);
        var session = new SqlSessionTemplate(factory.getObject());
        var properties = new EgonColaMybatisPlusProperties();
        var states = new OAuthSecurityStateRepositoryImpl(session.getMapper(OAuthSecurityStateMapper.class), properties,
                Mappers.getMapper(OAuthSecurityStateConverter.class), () -> "worker", Clock.fixed(NOW, ZoneOffset.UTC));
        service = new OAuthSubjectDeliveryOrderService(session.getMapper(SubjectDeliveryReceiptMapper.class), states,
                properties, () -> "worker", Clock.fixed(NOW, ZoneOffset.UTC));
        transaction = new TransactionTemplate(new DataSourceTransactionManager(source));
    }

    @Test void laterDeliveryRollsBackUntilPredecessorIsCommittedAndDuplicateIsIdempotent() {
        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.confirm(realm, "alice", 20L, 10L, "event-20", "a".repeat(64))))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_subject_delivery_receipt", Integer.class)).isZero();
        transaction.executeWithoutResult(status -> service.confirm(realm, "alice", 10L, 0L, "event-10", "a".repeat(64)));
        transaction.executeWithoutResult(status -> service.confirm(realm, "alice", 20L, 10L, "event-20", "a".repeat(64)));
        transaction.executeWithoutResult(status -> service.confirm(realm, "alice", 20L, 10L, "event-20", "a".repeat(64)));
        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.confirm(realm, "alice", 21L, 20L, "event-20", "a".repeat(64))))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.confirm(realm, "alice", 20L, 10L, "event-20", "b".repeat(64))))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tianquan_oauth.oauth_subject_delivery_receipt", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT version FROM tianquan_oauth.oauth_security_state WHERE id=42", Long.class)).isEqualTo(6L);
    }
}
