package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlManifestBO;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlResult;
import top.egon.cola.component.common.mybatis.ddl.EgonColaDdlTargetBO;
import top.egon.cola.component.common.mybatis.ddl.EgonColaPostgreDdlRunner;

import static org.assertj.core.api.Assertions.assertThat;

/** Opt-in fixture owns only one random schema in the explicitly supplied disposable PostgreSQL. */
@EnabledIfEnvironmentVariable(named = "SHOUBING_BASELINE_IT_ENABLED", matches = "true")
class OAuthFreshBaselinePostgresTest {
    @Test
    void freshBaselineRerunsAndPreservesFullyInstalledHistoricalChecksums() throws Exception {
        var source = new PGSimpleDataSource();
        source.setURL(System.getenv("SHOUBING_BASELINE_IT_JDBC_URL"));
        source.setUser(System.getenv("SHOUBING_BASELINE_IT_USER"));
        source.setPassword(Files.readString(Path.of(System.getenv("SHOUBING_BASELINE_IT_PASSWORD_FILE"))).stripTrailing());
        String schema = "idp_baseline_" + UUID.randomUUID().toString().replace("-", "");
        var mapper = new ObjectMapper();
        EgonColaDdlManifestBO manifest;
        try (var input = new ClassPathResource("db/egon-mp/repository-manifest.json").getInputStream()) {
            manifest = mapper.readValue(input, EgonColaDdlManifestBO.class);
        }
        try (var validators = Validation.buildDefaultValidatorFactory(); var connection = source.getConnection()) {
            try (var statement = connection.createStatement()) { statement.execute("CREATE SCHEMA " + schema); }
            try {
                var runner = new EgonColaPostgreDdlRunner(new ValidationUtils(validators.getValidator()),
                        new PathMatchingResourcePatternResolver(), Clock.systemUTC(),
                        Duration.ofSeconds(5), Duration.ofSeconds(30));
                var target = new EgonColaDdlTargetBO("isolated", schema, EgonColaDdlTargetBO.RoleEnum.MASTER_DATA,
                        source, manifest, "a".repeat(64));
                assertThat(runner.run(List.of(target))).extracting(EgonColaDdlResult::version)
                        .containsExactly(manifest.freshBaselineVersion());
                assertThat(runner.run(List.of(target))).extracting(EgonColaDdlResult::status)
                        .containsExactly(EgonColaDdlResult.StatusEnum.SKIPPED);
                try (var statement = connection.createStatement()) {
                    statement.execute("SET search_path TO " + schema + ",pg_catalog");
                    try (var columns = statement.executeQuery("SELECT count(*) FROM information_schema.columns WHERE table_schema = '"
                            + schema + "' AND table_name = 'oauth_security_state' AND column_name = 'directory_subject_ordered_revision'")) {
                        assertThat(columns.next()).isTrue();
                        assertThat(columns.getInt(1)).isOne();
                    }
                    // Represent an already installed historical schema using immutable original receipt facts.
                    // Its tables come from the verified fresh baseline; this fixture never rewrites owner history.
                    statement.execute("DELETE FROM ddl_history");
                }
                var original = manifest.scripts().subList(0, manifest.scripts().size() - 1);
                try (var insert = connection.prepareStatement("INSERT INTO ddl_history (tenant_id,script,type,version,checksum,installed_on,execution_ms,route_fingerprint) VALUES (0,?,'SQL',?,?,CURRENT_TIMESTAMP,0,?)")) {
                    for (var script : original) {
                        insert.setString(1, script.path()); insert.setString(2, script.version());
                        insert.setString(3, script.sha256()); insert.setString(4, target.routeFingerprint());
                        assertThat(insert.executeUpdate()).isOne();
                    }
                }
                var receiptsBefore = historicalReceipts(connection);
                var upgraded = runner.run(List.of(target));
                assertThat(upgraded).hasSize(manifest.scripts().size());
                assertThat(upgraded.subList(0, original.size())).allMatch(result -> result.status() == EgonColaDdlResult.StatusEnum.SKIPPED);
                assertThat(upgraded.getLast().status()).isEqualTo(EgonColaDdlResult.StatusEnum.APPLIED);
                assertThat(historicalReceipts(connection)).isEqualTo(receiptsBefore);
                assertThat(runner.run(List.of(target))).allMatch(result -> result.status() == EgonColaDdlResult.StatusEnum.SKIPPED);
            } finally {
                try (var statement = connection.createStatement()) {
                    statement.execute("SET search_path TO public,pg_catalog");
                    statement.execute("DROP SCHEMA " + schema + " CASCADE");
                }
            }
        }
    }

    private static List<String> historicalReceipts(java.sql.Connection connection) throws Exception {
        List<String> facts = new ArrayList<>();
        try (var statement = connection.createStatement(); var rows = statement.executeQuery(
                "SELECT version,checksum,route_fingerprint FROM ddl_history WHERE version < '20261122_001' ORDER BY version")) {
            while (rows.next()) { facts.add(rows.getString(1) + '|' + rows.getString(2) + '|' + rows.getString(3)); }
        }
        return List.copyOf(facts);
    }
}
