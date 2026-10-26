package top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.datasource.AbstractDataSource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

/** One-shot local command. Ordinary application startup never invokes this context. */
public final class PermissionIdentityBootstrapCli {
    public static final String COMMAND = "bootstrap-permission-identities";

    private PermissionIdentityBootstrapCli() { }

    public static int run(String[] arguments) {
        try {
            execute(arguments);
            System.out.println("PERMISSION_BOOTSTRAP_COMMITTED");
            return 0;
        } catch (Exception failure) {
            // Native SQL/driver errors may contain connection details; the protected journal is the recovery authority.
            System.err.println("PERMISSION_BOOTSTRAP_FAILED: inspect the protected command and journal; rerun the same operation after correcting the cause");
            return 1;
        }
    }

    static void execute(String[] arguments) throws IOException {
        if (arguments.length != 5 || !COMMAND.equals(arguments[0]) || !"--command-file".equals(arguments[1])
                || !"--receipt-file".equals(arguments[3])) { throw PermissionBootstrapFiles.rejected(); }
        Path commandFile = PermissionBootstrapFiles.path(arguments[2]), receiptFile = PermissionBootstrapFiles.path(arguments[4]);
        PermissionBootstrapFiles.directory(receiptFile.getParent());
        if (Files.exists(receiptFile, LinkOption.NOFOLLOW_LINKS)) { PermissionBootstrapFiles.file(receiptFile); }
        ObjectMapper mapper = mapper();
        var command = mapper.readValue(PermissionBootstrapFiles.read(commandFile, 262144), PermissionIdentityBootstrapCommand.class);
        try (var validation = jakarta.validation.Validation.buildDefaultValidatorFactory()) {
            PermissionIdentityBootstrap.validate(command, validation.getValidator());
        }
        var input = mapper.readValue(PermissionBootstrapFiles.read(PermissionBootstrapFiles.path(command.connectionFile()), 16384),
                PermissionIdentityBootstrapCommand.Connection.class);
        validateConnection(input);
        PermissionBootstrapFiles.directory(PermissionBootstrapFiles.path(command.credentialDirectory()));
        Map<String, Object> target = mapper.convertValue(input, new com.fasterxml.jackson.core.type.TypeReference<>() { });
        target.put("platformStoragePartitionId", Long.toString(input.platformStoragePartitionId()));
        target.put("platformManagementTenantId", Long.toString(input.platformManagementTenantId()));
        String digest = CanonicalJson.digest(Map.of("command", mapper.convertValue(command, Map.class), "target", target));
        boolean existingReceipt = Files.exists(receiptFile, LinkOption.NOFOLLOW_LINKS);
        if (existingReceipt) {
            var receipt = mapper.readTree(PermissionBootstrapFiles.read(receiptFile, 16384));
            if (!command.operationId().equals(receipt.path("operationId").asText())
                    || !digest.equals(receipt.path("commandDigest").asText())) { throw PermissionBootstrapFiles.rejected(); }
        }
        try (var context = open(input, command.operationId())) {
            var owner = new PermissionIdentityBootstrap(mapper, context.getBean(jakarta.validation.Validator.class),
                    context.getBean(org.springframework.transaction.PlatformTransactionManager.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.OAuthClientService.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.resource.service.ResourceServerService.class),
                    context.getBean(top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent.class),
                    context.getBean(java.time.Clock.class));
            var receipt = owner.execute(command, input.publicOrigin(), digest, existingReceipt);
            PermissionBootstrapFiles.receipt(receiptFile, mapper.writeValueAsBytes(receipt));
        }
    }

    static ObjectMapper mapper() {
        return JsonMapper.builder().addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS).build();
    }

    static void validateConnection(PermissionIdentityBootstrapCommand.Connection input) throws IOException {
        if (input == null || input.jdbcUrl() == null || !input.jdbcUrl().matches("jdbc:postgresql://[A-Za-z0-9.\\[\\]:-]+/[A-Za-z0-9_]+")
                || input.databaseName() == null || !input.databaseName().matches("[A-Za-z0-9_]{1,63}")
                || !input.jdbcUrl().endsWith("/" + input.databaseName()) || input.databaseOid() == null
                || !input.databaseOid().matches("[1-9][0-9]{0,9}") || input.username() == null
                || !input.username().matches("[A-Za-z_][A-Za-z0-9_-]{0,62}")
                || !input.username().equals(input.databaseOwner()) || input.publicOrigin() == null
                || !"https".equals(input.publicOrigin().getScheme()) || input.publicOrigin().getHost() == null
                || input.publicOrigin().getUserInfo() != null || input.publicOrigin().getQuery() != null
                || input.publicOrigin().getFragment() != null || !java.util.Set.of("", "/").contains(input.publicOrigin().getPath())
                || input.platformStoragePartitionId() <= 0 || input.platformManagementTenantId() <= 0
                || input.idMachineId() == null || input.idMachineId() < 0 || input.idMachineId() > 1023
                || input.keyId() == null || !input.keyId().matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) { throw PermissionBootstrapFiles.rejected(); }
        PermissionBootstrapFiles.file(PermissionBootstrapFiles.path(input.passwordFile()));
        byte[] key = PermissionBootstrapFiles.read(PermissionBootstrapFiles.path(input.keyFile()), 32);
        try { if (key.length != 32) { throw PermissionBootstrapFiles.rejected(); } }
        finally { Arrays.fill(key, (byte) 0); }
    }

    static AnnotationConfigApplicationContext open(PermissionIdentityBootstrapCommand.Connection input, String operationId) {
        var context = context(input, operationId);
        try { context.refresh(); return context; }
        catch (RuntimeException failure) { context.close(); throw failure; }
    }

    static AnnotationConfigApplicationContext context(PermissionIdentityBootstrapCommand.Connection input, String operationId) {
        var context = new AnnotationConfigApplicationContext();
        context.setBeanNameGenerator(new org.springframework.context.annotation.AnnotationBeanNameGenerator());
        context.getBeanFactory().setConversionService(org.springframework.boot.convert.ApplicationConversionService.getSharedInstance());
        // The explicit context has no application.yml or ambient environment configuration source.
        context.getEnvironment().getPropertySources().remove(org.springframework.core.env.StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        context.getEnvironment().getPropertySources().remove(org.springframework.core.env.StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("egon.tianquan-shoubing.identity-directory.platform-storage-partition-id", input.platformStoragePartitionId());
        properties.put("egon.tianquan-shoubing.oauth.platform-management-tenant-id", input.platformManagementTenantId());
        properties.put("egon.cola.component.id.machine-id", input.idMachineId());
        properties.put("egon.cola.component.mybatis-plus.tenant-id.ignored-tables[0]", "egon_cola_outbox_message");
        properties.put("egon.cola.component.transactional-outbox.node-id", "permission-bootstrap:" + operationId);
        properties.put("egon.cola.component.transactional-outbox.storage.data-source-bean-name", "dataSource");
        properties.put("egon.cola.component.transactional-outbox.storage.transaction-manager-bean-name", "transactionManager");
        properties.put("egon.cola.component.transactional-outbox.state-machine.business.enabled", "false");
        properties.put("egon.cola.component.transactional-outbox.storage.mp.auto-initialize-ddl", "false");
        properties.put("mybatis-plus.mapper-locations", "classpath*:mapper/**/*.xml");
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("permissionBootstrap", properties));
        context.registerBean("permissionBootstrapConnection", PermissionIdentityBootstrapCommand.Connection.class, () -> input);
        context.registerBean("permissionBootstrapPhysicalDataSource", javax.sql.DataSource.class, () -> guardedDataSource(input));
        context.register(PermissionIdentityBootstrapConfiguration.class);
        return context;
    }

    static javax.sql.DataSource guardedDataSource(PermissionIdentityBootstrapCommand.Connection input) {
        return new GuardedDataSource(input);
    }

    /** Exposes the native JavaBean metadata required by ShardingSphere while guarding every borrowed connection. */
    public static final class GuardedDataSource extends AbstractDataSource {
        private final PermissionIdentityBootstrapCommand.Connection input;

        GuardedDataSource(PermissionIdentityBootstrapCommand.Connection input) { this.input = input; }

        public String getUrl() { return input.jdbcUrl() + "?connectTimeout=5&socketTimeout=30"; }
        public String getUsername() { return input.username(); }
        @com.fasterxml.jackson.annotation.JsonIgnore
        public String getPassword() {
            byte[] bytes = null;
            try {
                bytes = PermissionBootstrapFiles.read(PermissionBootstrapFiles.path(input.passwordFile()), 4096);
                String password = new String(bytes, StandardCharsets.UTF_8).replaceFirst("\\r?\\n$", "");
                if (password.isEmpty()) { throw PermissionBootstrapFiles.rejected(); }
                return password;
            } catch (IOException failure) { throw new IllegalStateException("PERMISSION_BOOTSTRAP_CREDENTIAL_UNAVAILABLE", failure); }
            finally { if (bytes != null) { Arrays.fill(bytes, (byte) 0); } }
        }

        @Override public Connection getConnection() throws SQLException {
            Connection connection = java.sql.DriverManager.getConnection(getUrl(), getUsername(), getPassword());
            try { verifyDatabase(connection, input); return connection; }
            catch (RuntimeException | SQLException failure) {
                try { connection.close(); } catch (SQLException close) { failure.addSuppressed(close); }
                throw new SQLException("PERMISSION_BOOTSTRAP_TARGET_UNAVAILABLE", failure);
            }
        }
        @Override public Connection getConnection(String username, String password) { throw PermissionBootstrapFiles.rejected(); }
    }

    static void verifyDatabase(Connection connection, PermissionIdentityBootstrapCommand.Connection input) throws SQLException {
        try (var query = connection.prepareStatement("""
                select current_database(), d.oid::text, pg_get_userbyid(d.datdba), current_user
                from pg_database d where d.datname = current_database()
                """)) {
            query.setQueryTimeout(5);
            try (var rows = query.executeQuery()) {
                if (!rows.next() || !input.databaseName().equals(rows.getString(1)) || !input.databaseOid().equals(rows.getString(2))
                        || !input.databaseOwner().equals(rows.getString(3)) || !input.username().equals(rows.getString(4)) || rows.next()) {
                    throw new IllegalStateException("PERMISSION_BOOTSTRAP_TARGET_MISMATCH");
                }
            }
        }
    }

}
