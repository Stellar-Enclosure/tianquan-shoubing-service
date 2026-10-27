package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.junit.jupiter.api.Assertions.*;

/** Uses only an explicitly supplied, already running, empty isolated PostgreSQL schema. */
@EnabledIfEnvironmentVariable(named = "IDP_STATELESS_POSTGRES_IT", matches = "true")
class IdpOAuthStatePostgresqlIT {

    private static String url;
    private static Properties credentials;

    @BeforeAll
    static void initializeExplicitEmptyTarget() throws Exception {
        url = System.getenv("IDP_STATELESS_JDBC_URL");
        if (url == null || !url.startsWith("jdbc:postgresql://") || url.matches("(?is).*[?&](?:user|password)=.*")) {
            throw new IllegalArgumentException("IDP_IT_EXPLICIT_POSTGRES_URL_REQUIRED");
        }
        String file = System.getenv("IDP_STATELESS_CREDENTIAL_FILE");
        if (file == null) { throw new IllegalArgumentException("IDP_IT_CREDENTIAL_FILE_REQUIRED"); }
        Path path = Path.of(file);
        if (!Files.isRegularFile(path) || Files.isSymbolicLink(path)
                || !Files.getPosixFilePermissions(path).equals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))) {
            throw new IllegalArgumentException("IDP_IT_CREDENTIAL_FILE_UNSAFE");
        }
        credentials = new Properties();
        try (var input = Files.newInputStream(path)) { credentials.load(input); }
        if (!credentials.stringPropertyNames().equals(Set.of("user", "password"))) {
            throw new IllegalArgumentException("IDP_IT_CREDENTIAL_PROPERTIES_INVALID");
        }
        try (Connection connection = DriverManager.getConnection(url, credentials)) {
            try (var statement = connection.createStatement(); var rows = statement.executeQuery("select current_database()")) {
                assertTrue(rows.next());
                assertTrue(rows.getString(1).endsWith("_idp_stateless_it"), "A dedicated IDP test database is required");
            }
            try (var statement = connection.createStatement(); var rows = statement.executeQuery("""
                    select count(*) from information_schema.tables where table_schema = 'tianquan_oauth'
                    """)) {
                assertTrue(rows.next()); assertEquals(0L, rows.getLong(1), "The supplied schema must be empty");
            }
            try (var statement = connection.createStatement(); var rows = statement.executeQuery("""
                    select count(*) from pg_namespace where nspname = 'tianquan_oauth'
                    """)) {
                assertTrue(rows.next()); assertEquals(1L, rows.getLong(1), "The operator must provision the schema first");
            }
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                statement.execute("set local search_path to tianquan_oauth, pg_catalog");
                for (String script : new String[]{"V20261008_001__initialize_oauth_tenant_schema.sql",
                        "V20261009_001__support_oauth_consent_state.sql", "V20261023_001__stateless_oauth_state.sql"}) {
                    try (var input = IdpOAuthStatePostgresqlIT.class.getClassLoader().getResourceAsStream("db/egon-mp/" + script)) {
                        assertNotNull(input); statement.execute(new String(input.readAllBytes(), StandardCharsets.UTF_8));
                    }
                }
            }
            connection.commit();
        }
    }

    @Test
    void authenticationIdentityIsUniqueWithinTheTrustedPartition() throws Exception {
        try (Connection connection = open()) {
            authentication(connection, 101L, 101L, "a".repeat(64));
            SQLException conflict = assertThrows(SQLException.class,
                    () -> authentication(connection, 102L, 101L, "a".repeat(64)));
            assertEquals("23505", conflict.getSQLState());
            authentication(connection, 103L, 102L, "a".repeat(64));
        }
    }

    @Test
    void twoConnectionsCannotConsumeTheSameInteraction() throws Exception {
        try (Connection seed = open()) { interaction(seed, 201L, "once"); }
        try (Connection winner = open(); Connection loser = open(); var executor = Executors.newSingleThreadExecutor()) {
            winner.setAutoCommit(false); loser.setAutoCommit(false);
            assertEquals(1, consume(winner, "once"));
            var pending = executor.submit(() -> {
                int changed = consume(loser, "once"); loser.commit(); return changed;
            });
            winner.commit();
            assertEquals(0, pending.get(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void tokenCasRollsBackAndOnlyOneConcurrentWriterSucceeds() throws Exception {
        String table = "it_token_" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        boolean created = false;
        try {
            try (Connection seed = open(); var statement = seed.createStatement()) {
                statement.execute("CREATE TABLE tianquan_oauth." + table
                        + " (LIKE tianquan_oauth.oauth_token INCLUDING DEFAULTS INCLUDING CONSTRAINTS)");
                created = true;
                statement.execute("INSERT INTO tianquan_oauth." + table
                        + " (id,tenant_id,version,create_time,create_user_id,update_time,update_user_id,authorization_pk,"
                        + "token_type,token_digest,issued_at,expires_at,metadata_ciphertext,refresh_generation,retain_until) "
                        + "VALUES (401,201,0,CURRENT_TIMESTAMP,'it',CURRENT_TIMESTAMP,'it',501,'REFRESH',repeat('a',64),"
                        + "CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + interval '1 hour','ENC:test',0,CURRENT_TIMESTAMP + interval '25 hours')");
            }
            var configuration = new org.apache.ibatis.session.Configuration();
            String resource = "mapper/token/OAuthTokenMapper.xml";
            try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
                new org.apache.ibatis.builder.xml.XMLMapperBuilder(input, configuration, resource,
                        configuration.getSqlFragments()).parse();
            }
            var row = new top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthTokenPO();
            String updateSql = configuration.getMappedStatement(
                    "top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthTokenMapper.updateExpectedVersion")
                    .getBoundSql(java.util.Map.of("tenantId", 201L, "po", row, "expectedVersion", 0L)).getSql()
                    .replace("tianquan_oauth.oauth_token", "tianquan_oauth." + table);
            try (Connection rollback = open()) {
                rollback.setAutoCommit(false);
                assertEquals(1, updateToken(rollback, updateSql));
                rollback.rollback();
            }
            var ready = new java.util.concurrent.CountDownLatch(2);
            var start = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Callable<Integer> writer = () -> {
                try (Connection connection = open()) {
                    connection.setAutoCommit(false);
                    try (var query = connection.createStatement();
                         var rows = query.executeQuery("SELECT version FROM tianquan_oauth." + table + " WHERE id=401")) {
                        assertTrue(rows.next()); assertEquals(0L, rows.getLong(1));
                    }
                    ready.countDown();
                    if (!start.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("TOKEN_CAS_START_TIMEOUT");
                    int changed = updateToken(connection, updateSql);
                    connection.commit();
                    return changed;
                }
            };
            try (var workers = Executors.newFixedThreadPool(2)) {
                var first = workers.submit(writer);
                var second = workers.submit(writer);
                assertTrue(ready.await(10, TimeUnit.SECONDS));
                start.countDown();
                assertEquals(1, first.get(20, TimeUnit.SECONDS) + second.get(20, TimeUnit.SECONDS));
            } finally {
                start.countDown();
            }
        } finally {
            if (created) {
                try (Connection connection = open(); var statement = connection.createStatement()) {
                    statement.execute("DROP TABLE tianquan_oauth." + table);
                }
            }
        }
    }

    private static int updateToken(Connection connection, String sql) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            var now = java.sql.Timestamp.from(java.time.Instant.now());
            statement.setTimestamp(1, now);
            statement.setNull(2, java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            statement.setString(3, "ENC:test");
            statement.setLong(4, 1L);
            statement.setString(5, "it");
            statement.setTimestamp(6, now);
            statement.setLong(7, 201L);
            statement.setLong(8, 401L);
            statement.setLong(9, 501L);
            statement.setString(10, "a".repeat(64));
            statement.setString(11, "REFRESH");
            statement.setLong(12, 0L);
            return statement.executeUpdate();
        }
    }

    @Test
    void expiredInteractionCannotBeConsumedEvenWithCorrectVersion() throws Exception {
        try (Connection connection = open()) {
            interaction(connection, 202L, "expired");
            try (var update = connection.prepareStatement("""
                    update oauth_interaction set create_time = current_timestamp - interval '6 minutes',
                      expires_at = current_timestamp - interval '1 minute'
                    where tenant_id = 201 and interaction_id = 'expired'
                    """)) { assertEquals(1, update.executeUpdate()); }
            assertEquals(0, consume(connection, "expired"));
        }
    }

    @Test
    void inboxAndReceiptFailureCannotLeaveACommittedPartialHandoff() throws Exception {
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                statement.executeUpdate("""
                        insert into oauth_audit_inbox (id, tenant_id, version, create_time, create_user_id,
                          update_time, update_user_id, event_id, event_fingerprint, schema_version, source_client_pk,
                          source_issuer, source_resource_uri, event_payload, occurred_at, received_at, state,
                          attempt_count, next_attempt_at, claim_generation, processing_deadline, retain_until)
                        values (301,301,0,current_timestamp,'it',current_timestamp,'it','rollback-event',repeat('a',64),
                          1,1,'https://idp.example/tenants/301','https://api.example/orders','{}',current_timestamp,
                          current_timestamp,'PENDING',0,current_timestamp,0,current_timestamp + interval '1 hour',
                          current_timestamp + interval '181 days')
                        """);
                SQLException missingFinalAudit = assertThrows(SQLException.class, () -> statement.executeUpdate("""
                        insert into oauth_audit_receipt (id, tenant_id, version, create_time, create_user_id,
                          update_time, update_user_id, receipt_id, inbox_pk, event_id, event_fingerprint,
                          source_client_pk, source_issuer, source_resource_uri, outcome, audit_pk, confirmed_at, retain_until)
                        values (302,301,0,current_timestamp,'it',current_timestamp,'it','receipt',301,'rollback-event',repeat('a',64),
                          1,'https://idp.example/tenants/301','https://api.example/orders','STORED',999,current_timestamp,
                          current_timestamp + interval '181 days')
                        """));
                assertEquals("23503", missingFinalAudit.getSQLState());
            }
            connection.rollback();
        }
        try (Connection connection = open(); var statement = connection.createStatement();
                var rows = statement.executeQuery("select count(*) from oauth_audit_inbox where tenant_id=301 and event_id='rollback-event'")) {
            assertTrue(rows.next()); assertEquals(0, rows.getInt(1));
        }
    }

    private static Connection open() throws SQLException {
        Connection connection = DriverManager.getConnection(url, credentials);
        connection.setSchema("tianquan_oauth");
        return connection;
    }

    private static void authentication(Connection connection, long id, long tenant, String digest) throws SQLException {
        try (var insert = connection.prepareStatement("""
                insert into oauth_authentication (id,tenant_id,version,create_time,create_user_id,update_time,update_user_id,
                  jti_digest,subject,browser_binding_digest,subject_generation,realm_generation,authenticated_at,acr,
                  status,expires_at,retain_until)
                values (?,?,0,current_timestamp,'it',current_timestamp,'it',?,'subject',repeat('b',64),0,0,
                  current_timestamp,'PASSWORD','ACTIVE',current_timestamp + interval '8 hours',current_timestamp + interval '32 hours')
                """)) {
            insert.setLong(1, id); insert.setLong(2, tenant); insert.setString(3, digest); insert.executeUpdate();
        }
    }

    private static void interaction(Connection connection, long id, String key) throws SQLException {
        try (var insert = connection.prepareStatement("""
                insert into oauth_interaction (id,tenant_id,version,create_time,create_user_id,update_time,update_user_id,
                  interaction_id,purpose,request_digest,request_ciphertext,browser_binding_digest,csrf_digest,
                  requested_scopes,approved_scopes,state,expires_at,retain_until)
                values (?,201,0,current_timestamp,'it',current_timestamp,'it',?,'PASSWORD_CHANGE',repeat('a',64),
                  'ENC:bounded',repeat('b',64),repeat('c',64),'[]','[]','PENDING',
                  current_timestamp + interval '5 minutes',current_timestamp + interval '25 hours')
                """)) { insert.setLong(1, id); insert.setString(2, key); insert.executeUpdate(); }
    }

    private static int consume(Connection connection, String key) throws SQLException {
        try (var update = connection.prepareStatement("""
                update oauth_interaction set state='CONSUMED', consumed_at=current_timestamp, version=version+1
                where tenant_id=201 and interaction_id=? and version=0 and state='PENDING' and expires_at>current_timestamp
                """)) { update.setQueryTimeout(5); update.setString(1, key); return update.executeUpdate(); }
    }
}
