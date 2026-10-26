package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.session.Configuration;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthAuthenticationConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthInteractionConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthInteractionPO;

import static org.junit.jupiter.api.Assertions.*;

class IdpStatelessSchemaContractTest {

    private static final String MIGRATION = "db/egon-mp/V20261023_001__stateless_oauth_state.sql";
    private static final String FROZEN_SHA = "21134dca1334ff8af42ac455fd3b2b584f06c29f92846a7bf565a1625115ea13";
    private static final String BASE = "top.egon.cola.platform.tianquan.shoubing.admin.";

    @Test
    void manifestContainsTheOneFrozenVersionAndUnchangedHistory() throws Exception {
        var scripts = new ObjectMapper().readTree(bytes("db/egon-mp/repository-manifest.json")).path("scripts");
        assertEquals(3, scripts.size());
        assertEquals("238adf24fc3025f27ac5da91528b6110962977762f3ce751467a970a7c6acc23", scripts.get(0).path("sha256").asText());
        assertEquals("89210d641e6018b5c1e87a394bbe9d99eb90f64a7f86217ce2ec40a90afad5db", scripts.get(1).path("sha256").asText());
        for (var script : scripts) {
            assertEquals(script.path("sha256").asText(), sha(bytes(script.path("path").asText())));
        }
        assertEquals(MIGRATION, scripts.get(2).path("path").asText());
        assertEquals(FROZEN_SHA, sha(bytes(MIGRATION)));
    }

    @Test
    void finalScriptRejectsLegacyStateAndDoesNotResetIt() throws Exception {
        String sql = text(MIGRATION).replaceAll("(?m)--[^\\n]*", "");
        assertTrue(sql.contains("STATELESS_OAUTH_CLEAN_STATE_REQUIRED"));
        assertFalse(sql.matches("(?s).*\\b(?:DELETE\\s+FROM|TRUNCATE)\\b.*"));
        assertTrue(sql.contains("authorized_scopes <@ requested_scopes"));
        assertTrue(sql.contains("code_challenge_method IS NOT NULL"));
        assertTrue(sql.contains("lease_until <= processing_deadline"));
        assertTrue(sql.contains("DROP COLUMN projection_status"));
    }

    @Test
    void everyNewAuthorityTableHasAnExplicitPhysicalRoute() throws Exception {
        String routes = text("oauth-sharding-native.yml");
        for (String table : List.of("oauth_authentication", "oauth_interaction", "oauth_audit_inbox",
                "oauth_audit_receipt", "oauth_audit_dead_letter")) {
            assertTrue(routes.contains("oauth_primary.tianquan_oauth." + table), table);
        }
    }

    @Test
    void mapperLookupsAndUpdatesCarryTenantAndVersionBoundaries() throws Exception {
        for (String entry : List.of("oauth.OAuthAuthentication", "oauth.OAuthInteraction", "audit.OAuthAuditInbox",
                "audit.OAuthAuditReceipt", "audit.OAuthAuditDeadLetter")) {
            String[] names = entry.split("\\.");
            String resource = "mapper/" + names[0] + "/" + names[1] + "Mapper.xml";
            Configuration configuration = new Configuration();
            try (InputStream input = required(resource)) {
                new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
            }
            String namespace = BASE + names[0] + ".dao." + names[1] + "Mapper.";
            var select = configuration.getMappedStatement(namespace + "selectByKeyForUpdate")
                    .getBoundSql(Map.of("tenantId", 101L, "key", "stable"));
            assertTrue(select.getSql().contains("tenant_id = ?"));
            assertTrue(select.getSql().contains("FOR UPDATE"));
            var update = configuration.getMappedStatement(namespace + "updateExpectedVersion").getBoundSql(null);
            assertTrue(update.getSql().contains("tenant_id = ?"));
            assertTrue(update.getSql().contains("version = ?"));
            assertTrue(update.getSql().contains("deleted_at IS NULL"));
        }
    }

    @Test
    void consumedRefreshHistoryIsNotHiddenFromTheDigestRepository() throws Exception {
        String tokenMapper = text("mapper/token/OAuthTokenMapper.xml");
        String lookup = tokenMapper.substring(tokenMapper.indexOf("<select id=\"selectByTokenDigest\""));
        lookup = lookup.substring(0, lookup.indexOf("</select>"));
        assertFalse(lookup.contains("consumed_at IS NULL"));
        assertFalse(lookup.contains("expires_at &gt;"));
        assertTrue(text(MIGRATION).contains("retain_until >= expires_at + INTERVAL '24 hours'"));
    }

    @Test
    void protocolBindingSurvivesActualGeneratedConvertersWithoutSecretLogging() throws Exception {
        OAuthInteractionPO row = new OAuthInteractionPO();
        row.setId(42L);
        row.setVersion(3L);
        row.setInteractionId("interaction-1").setBrowserBindingDigest("b".repeat(64))
                .setClientBrowserBindingDigest("c".repeat(64)).setRequestCiphertext("ENC:request-secret")
                .setRequestedScopes(List.of("openid", "orders:read")).setApprovedScopes(List.of("openid"));
        var converter = Mappers.getMapper(OAuthInteractionConverter.class);
        var value = converter.toTarget(row);
        var restored = converter.toSource(value);
        assertEquals(row.getInteractionId(), restored.getInteractionId());
        assertEquals(row.getClientBrowserBindingDigest(), restored.getClientBrowserBindingDigest());
        assertEquals(row.getRequestedScopes(), restored.getRequestedScopes());
        assertEquals(row.getApprovedScopes(), restored.getApprovedScopes());
        assertFalse(value.toString().contains("request-secret"));
        assertFalse(new ObjectMapper().writeValueAsString(value).contains("request-secret"));
    }

    @Test
    void authenticationFactsContainNoTokenOrSecurityContext() {
        OAuthAuthenticationBO value = OAuthAuthenticationBO.builder().jtiDigest("a".repeat(64))
                .browserBindingDigest("b".repeat(64)).subject("subject-private").version(2L).build();
        var row = Mappers.getMapper(OAuthAuthenticationConverter.class).toSource(value);
        assertEquals(value.getJtiDigest(), row.getJtiDigest());
        assertFalse(value.toString().contains("subject-private"));
        for (var field : row.getClass().getDeclaredFields()) {
            assertFalse(field.getName().toLowerCase().contains("securitycontext"));
            assertFalse(field.getName().toLowerCase().contains("tokenvalue"));
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String text(String resource) throws Exception {
        return new String(bytes(resource), StandardCharsets.UTF_8);
    }

    private static byte[] bytes(String resource) throws Exception {
        try (InputStream input = required(resource)) { return input.readAllBytes(); }
    }

    private static InputStream required(String resource) {
        InputStream input = IdpStatelessSchemaContractTest.class.getClassLoader().getResourceAsStream(resource);
        assertNotNull(input, resource);
        return input;
    }
}
