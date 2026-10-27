package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import java.io.InputStream;
import java.util.Map;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.session.Configuration;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthDeviceSessionConverter;

import static org.junit.jupiter.api.Assertions.*;

class DeviceSessionPersistenceContractTest {
    private static final String NAMESPACE = "top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthDeviceSessionMapper.";

    @Test void sessionQueriesAndUpdatesKeepTenantOwnerAndVersionBoundaries() throws Exception {
        Configuration configuration = new Configuration();
        String resource = "mapper/oauth/OAuthDeviceSessionMapper.xml";
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resource)) {
            assertNotNull(input);
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        String live = configuration.getMappedStatement(NAMESPACE + "selectLiveBySubject")
                .getBoundSql(Map.of("tenantId", 7L, "subject", "alice", "now", java.time.Instant.now())).getSql();
        assertTrue(live.contains("s.tenant_id = ? AND s.subject = ?"));
        assertTrue(live.contains("g.device_session_id = s.id"));
        assertTrue(live.contains("a.subject_generation = u.generation"));
        assertTrue(live.contains("a.realm_generation = r.generation"));
        String update = configuration.getMappedStatement(NAMESPACE + "updateExpectedVersion").getBoundSql(null).getSql();
        assertTrue(update.contains("tenant_id = ? AND id = ? AND version = ?"));
        String retention = configuration.getMappedStatement(NAMESPACE + "deleteRetained").getBoundSql(null).getSql();
        assertTrue(retention.contains("g.device_session_id = s.id AND g.deleted_at IS NULL"));
        assertTrue(retention.contains("a.expires_at <= ? - INTERVAL '24 hours'"));
    }

    @Test void generatedConverterPreservesTheStableSessionAndSsoBinding() {
        var converter = Mappers.getMapper(OAuthDeviceSessionConverter.class);
        var source = OAuthDeviceSessionBO.builder().id(15L).version(3L).subject("alice").clientPk(11L)
                .authenticationJtiDigest("a".repeat(64)).userAgent("Android").ipAddress("192.0.2.1").status("ACTIVE").build();
        assertEquals(source, converter.toTarget(converter.toSource(source)));
    }
}
