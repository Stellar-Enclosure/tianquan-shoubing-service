package top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.dto.CreateOAuthClientDTO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.vo.CreatedOAuthClientVO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.OAuthClientService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.service.ResourceServerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

class PermissionIdentityBootstrapTest {
    private static final URI ORIGIN = URI.create("https://idp.example");
    private static final URI ISSUER = URI.create("https://idp.example/platform");
    private static final String OPERATION = "ab5ec3c6-daa7-4f11-b165-07aff63fd159";
    private static final String DIGEST = "a".repeat(64);
    @TempDir Path directory;
    private final com.fasterxml.jackson.databind.ObjectMapper mapper = PermissionIdentityBootstrapCli.mapper();
    private final jakarta.validation.ValidatorFactory validators = jakarta.validation.Validation.buildDefaultValidatorFactory();
    private final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthResourceRepository resources = mock(OAuthResourceRepository.class);
    private final OAuthAuditRepository audits = mock(OAuthAuditRepository.class);
    private final OAuthClientService clientService = mock(OAuthClientService.class);
    private final ResourceServerService resourceService = mock(ResourceServerService.class);
    private final OAuthSecurityProjectionComponent security = mock(OAuthSecurityProjectionComponent.class);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(ISSUER).realmKey("platform")
            .realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(1L).build();
    private final OAuthClientBO client = OAuthClientBO.builder().id(123L).clientId("bootstrap-client").credentialVersion(1L).build();
    private final SimpleTransactionStatus status = new SimpleTransactionStatus();
    private PermissionIdentityBootstrap owner;
    private PermissionIdentityBootstrapCommand command;
    private OAuthAuditBO saved;

    @BeforeEach
    void prepare() throws Exception {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        owner = new PermissionIdentityBootstrap(mapper, validators.getValidator(), transactions, issuers, realms, clients,
                resources, audits, clientService, resourceService, security, Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC));
        var input = CreateOAuthClientDTO.builder().clientId("bootstrap-client").appId("bootstrap-client")
                .clientName("Bootstrap fixture").clientType(OAuthClient.ClientType.CONFIDENTIAL).purpose(OAuthClientPurposeEnum.SERVICE)
                .accessTokenTtlSeconds(300).refreshTokenTtlSeconds(0).redirectUris(List.of()).resourceUris(List.of()).allowedScopes(List.of()).build();
        command = new PermissionIdentityBootstrapCommand(1, OPERATION, directory.resolve("connection.json").toString(),
                directory.toString(), "operator-1", List.of(new PermissionIdentityBootstrapCommand.Client(ISSUER, input)), List.of(), List.of());
        when(transactions.getTransaction(any())).thenReturn(status);
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(realm);
        when(realms.findByRealmKeyForUpdate(realm)).thenReturn(Optional.of(OAuthRealmBO.builder().status("ACTIVE").build()));
        when(security.isIssuerReady(realm)).thenReturn(true);
        when(clients.findByClientId(realm, "bootstrap-client")).thenReturn(Optional.empty(), Optional.of(client));
        when(clientService.create(eq(realm), eq(realm), any(), eq("operator-1")))
                .thenAnswer(call -> CreatedOAuthClientVO.builder().clientId("bootstrap-client").clientSecret("fixture-credential").build());
        when(audits.save(eq(realm), any(), anyLong())).thenAnswer(call -> { saved = call.getArgument(1); return saved; });
    }

    @Test
    void commitsNativeOwnerAndPrivateMaterialWithOneImmutableAuditReceipt() throws Exception {
        JsonNode receipt = owner.execute(command, ORIGIN, DIGEST);
        verify(transactions).commit(status);
        verify(clientService).create(eq(realm), eq(realm), any(), eq("operator-1"));
        verifyNoInteractions(resourceService);
        assertThat(saved.getPayload()).isEqualTo(receipt);
        assertThat(receipt.toString()).doesNotContain("fixture-credential");
        Path credential = directory.resolve(receipt.path("clients").get(0).path("file").asText());
        assertThat(Files.readString(credential)).isEqualTo("fixture-credential");
        assertThat(Files.getPosixFilePermissions(credential)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        PermissionBootstrapFiles.receipt(directory.resolve("receipt.json"), mapper.writeValueAsBytes(receipt));
        PermissionBootstrapFiles.receipt(directory.resolve("receipt.json"), mapper.writeValueAsBytes(receipt));
        assertThatThrownBy(() -> PermissionBootstrapFiles.receipt(directory.resolve("receipt.json"), "{}".getBytes(StandardCharsets.UTF_8)))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
    }

    @Test
    void committedAuditResumesProjectionWithoutCreatingOrRotatingAgain() throws Exception {
        JsonNode receipt = owner.execute(command, ORIGIN, DIGEST);
        when(audits.findByEventId(realm, "permission-bootstrap-" + OPERATION)).thenReturn(Optional.of(saved));
        org.mockito.Mockito.clearInvocations(clientService, resourceService, audits);
        assertThat(owner.execute(command, ORIGIN, DIGEST)).isEqualTo(receipt);
        verifyNoInteractions(clientService, resourceService);
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, "b".repeat(64))).hasMessage("PERMISSION_BOOTSTRAP_STATE_CONFLICT");
        client.setCredentialVersion(2L);
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, DIGEST)).hasMessage("PERMISSION_BOOTSTRAP_STATE_CONFLICT");
    }

    @Test
    void uncertainCommitKeepsJournalAndCredentialForAuditBasedRecovery() throws Exception {
        org.mockito.Mockito.doThrow(new org.springframework.transaction.TransactionSystemException("commit outcome unknown"))
                .when(transactions).commit(status);
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, DIGEST)).isInstanceOf(org.springframework.transaction.TransactionSystemException.class);
        assertThat(Files.exists(directory.resolve(OPERATION + ".pending.json"))).isTrue();
        assertThat(Files.exists(directory.resolve(saved.getPayload().path("clients").get(0).path("file").asText()))).isTrue();
        when(audits.findByEventId(realm, "permission-bootstrap-" + OPERATION)).thenReturn(Optional.of(saved));
        org.mockito.Mockito.doNothing().when(transactions).commit(status);
        org.mockito.Mockito.clearInvocations(clientService);
        assertThat(owner.execute(command, ORIGIN, DIGEST)).isEqualTo(saved.getPayload());
        verifyNoInteractions(clientService);
    }

    @Test
    void credentialCollisionRollsBackAndDoesNotOverwriteForeignMaterial() throws Exception {
        String name = OPERATION + "-" + PermissionBootstrapFiles.digest((ISSUER + "|bootstrap-client").getBytes(StandardCharsets.UTF_8)).substring(0, 24) + ".credential";
        PermissionBootstrapFiles.create(directory.resolve(name), "foreign-material".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, DIGEST)).hasMessage("PERMISSION_BOOTSTRAP_CREDENTIAL_WRITE_FAILED");
        verify(transactions).rollback(status);
        assertThat(saved).isNull();
        assertThat(Files.readString(directory.resolve(name))).isEqualTo("foreign-material");
    }

    @Test
    void rollbackRetryRequiresAllNativeIdentitiesAbsentAndMatchingPrivateFiles() throws Exception {
        org.mockito.Mockito.doThrow(new org.springframework.transaction.TransactionSystemException("rollback completed"))
                .when(transactions).commit(status);
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, DIGEST)).isInstanceOf(org.springframework.transaction.TransactionSystemException.class);
        org.mockito.Mockito.doNothing().when(transactions).commit(status);
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, DIGEST)).hasMessage("PERMISSION_BOOTSTRAP_STATE_CONFLICT");
        when(clients.findByClientId(realm, "bootstrap-client")).thenReturn(Optional.empty(), Optional.of(client));
        assertThat(owner.execute(command, ORIGIN, DIGEST).path("operationId").asText()).isEqualTo(OPERATION);
    }

    @Test
    void existingReceiptCannotBootstrapAnEmptyOrDifferentDatabase() {
        assertThatThrownBy(() -> owner.execute(command, ORIGIN, DIGEST, true)).hasMessage("PERMISSION_BOOTSTRAP_STATE_CONFLICT");
        verifyNoInteractions(clientService, resourceService);
    }

    @Test
    void unsafeFilesAndMalformedCliAreRejectedBeforeDatabaseOrNativeOwner() throws Exception {
        Path file = directory.resolve("command.json");
        Files.writeString(file, "{}");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
        assertThatThrownBy(() -> PermissionIdentityBootstrapCli.execute(new String[] {PermissionIdentityBootstrapCli.COMMAND,
                "--command-file", file.toString(), "--receipt-file", directory.resolve("receipt.json").toString()}))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        Path link = directory.resolve("link.json"); Files.createSymbolicLink(link, file);
        assertThatThrownBy(() -> PermissionBootstrapFiles.read(link, 1024)).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThatThrownBy(() -> PermissionIdentityBootstrapCli.execute(new String[] {PermissionIdentityBootstrapCli.COMMAND, "--password", "unused"}))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        verifyNoInteractions(transactions, clientService, resourceService);
    }

    @Test
    void privateChildrenUnderANonStickyWritableAncestorCannotSupplyCommandsOrSecrets() throws Exception {
        Path shared = Files.createDirectory(directory.resolve("shared"));
        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxrwxrwx"));
        Path child = Files.createDirectory(shared.resolve("private"));
        Files.setPosixFilePermissions(child, PosixFilePermissions.fromString("rwx------"));
        Path unsafeCommand = child.resolve("command.json"), unsafeSecret = child.resolve("password");
        Files.write(unsafeCommand, mapper.writeValueAsBytes(command)); Files.writeString(unsafeSecret, "private-secret");
        for (Path file : List.of(unsafeCommand, unsafeSecret)) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            assertThatThrownBy(() -> PermissionBootstrapFiles.read(file, 262144)).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        }
        assertThatThrownBy(() -> PermissionIdentityBootstrapCli.execute(new String[]{PermissionIdentityBootstrapCli.COMMAND,
                "--command-file", unsafeCommand.toString(), "--receipt-file", directory.resolve("receipt.json").toString()}))
                .hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThatThrownBy(() -> PermissionBootstrapFiles.receipt(child.resolve("receipt.json"), new byte[]{1})).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        verifyNoInteractions(transactions, clientService, resourceService);
    }

    @Test
    void aTrustedRealDirectoryCannotBeReachedThroughAnUntrustedAncestorAlias() throws Exception {
        Path anchor = Files.createDirectory(directory.resolve("anchor"));
        Path child = Files.createDirectory(anchor.resolve("private"));
        Files.setPosixFilePermissions(anchor, PosixFilePermissions.fromString("rwx------"));
        Files.setPosixFilePermissions(child, PosixFilePermissions.fromString("rwx------"));
        Path secret = child.resolve("password");
        PermissionBootstrapFiles.create(secret, "private-secret".getBytes(StandardCharsets.UTF_8));
        Path shared = Files.createDirectory(directory.resolve("shared"));
        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxrwxrwx"));
        Path alias = shared.resolve("alias"); Files.createSymbolicLink(alias, anchor);
        assertThatThrownBy(() -> PermissionBootstrapFiles.read(alias.resolve("private/password"), 1024)).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        assertThat(PermissionBootstrapFiles.read(secret, 1024)).isEqualTo("private-secret".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void bootstrapIsNotAnAutomaticHostLifecycleOrScannedConfiguration() {
        assertThat(org.springframework.beans.factory.SmartInitializingSingleton.class.isAssignableFrom(IdpDevelopmentClientBootstrap.class)).isFalse();
        var scanner = new org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new org.springframework.core.type.filter.AnnotationTypeFilter(org.springframework.stereotype.Component.class));
        assertThat(scanner.findCandidateComponents("top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap"))
                .noneMatch(bean -> PermissionIdentityBootstrapConfiguration.class.getName().equals(bean.getBeanClassName()));
        assertThat(PermissionIdentityBootstrapConfiguration.class.getAnnotation(org.springframework.context.annotation.Import.class).value())
                .noneMatch(type -> org.springframework.boot.ApplicationRunner.class.isAssignableFrom(type)
                        || org.springframework.boot.CommandLineRunner.class.isAssignableFrom(type));
    }

    @Test
    void guardedDataSourceKeepsNativeShardingMetadataAndRejectsCredentialOverride() throws Exception {
        Path password = directory.resolve("database-password");
        PermissionBootstrapFiles.create(password, "fixture-password\n".getBytes(StandardCharsets.UTF_8));
        var input = new PermissionIdentityBootstrapCommand.Connection("jdbc:postgresql://127.0.0.1:5432/fixture", "fixture", "42",
                "fixture_owner", "fixture_owner", password.toString(), ORIGIN, 1L, 0, 1001L, "fixture-key", directory.resolve("key").toString());
        var source = PermissionIdentityBootstrapCli.guardedDataSource(input);
        var properties = org.apache.shardingsphere.infra.datasource.pool.props.creator.DataSourcePoolPropertiesCreator.create(source)
                .getConnectionPropertySynonyms().getStandardProperties();
        assertThat(properties).containsEntry("url", input.jdbcUrl() + "?connectTimeout=5&socketTimeout=30")
                .containsEntry("username", "fixture_owner").containsEntry("password", "fixture-password");
        assertThatThrownBy(() -> source.getConnection("foreign", "unused")).hasMessage("PERMISSION_BOOTSTRAP_INPUT_UNSAFE");
        var connection = mock(java.sql.Connection.class);
        var query = mock(java.sql.PreparedStatement.class);
        var rows = mock(java.sql.ResultSet.class);
        when(connection.prepareStatement(any())).thenReturn(query); when(query.executeQuery()).thenReturn(rows);
        when(rows.next()).thenReturn(true, false);
        when(rows.getString(1)).thenReturn("fixture"); when(rows.getString(2)).thenReturn("43");
        when(rows.getString(3)).thenReturn("fixture_owner"); when(rows.getString(4)).thenReturn("fixture_owner");
        assertThatThrownBy(() -> PermissionIdentityBootstrapCli.verifyDatabase(connection, input))
                .hasMessage("PERMISSION_BOOTSTRAP_TARGET_MISMATCH");
        verify(query).close(); verify(rows).close();
    }

    @org.junit.jupiter.api.AfterEach
    void closeValidators() { validators.close(); }

    @Test
    void explicitContextImportsOnlyPersistenceAndProducerInfrastructureBeforeAnyConnection() {
        try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.register(PermissionIdentityBootstrapConfiguration.class);
            var reached = new java.util.concurrent.atomic.AtomicBoolean();
            context.addBeanFactoryPostProcessor(factory -> {
                assertThat(factory.containsBeanDefinition("transactionalOutbox")).isTrue();
                assertThat(factory.containsBeanDefinition("transactionManager")).isTrue();
                assertThat(factory.containsBeanDefinition("oAuthClientRepository")).isTrue();
                for (String name : factory.getBeanDefinitionNames()) {
                    String type = factory.getBeanDefinition(name).getBeanClassName();
                    if (type != null) {
                        assertThat(type).doesNotContain("IdpAdminApplication", "IdpDevelopmentClientBootstrap", "OAuthMigrationRunner",
                                "DeliveryDispatcher", "OutboxDispatch", "OutboxMaintenance", "EnableScheduling", "RpcProvider");
                    }
                }
                reached.set(true);
                throw new IllegalStateException("BOOTSTRAP_GRAPH_VERIFIED_BEFORE_DATABASE");
            });
            assertThatThrownBy(context::refresh).hasMessageContaining("BOOTSTRAP_GRAPH_VERIFIED_BEFORE_DATABASE");
            assertThat(reached).isTrue();
        }
    }

    @Test
    void completeOwnerContextUsesOneTransactionDataSourceWithoutStartingDeliveryOrWeb() throws Exception {
        Path key = directory.resolve("encryption-key");
        PermissionBootstrapFiles.create(key, new byte[32]);
        var input = new PermissionIdentityBootstrapCommand.Connection("jdbc:postgresql://127.0.0.1:5432/fixture", "fixture", "42",
                "fixture_owner", "fixture_owner", directory.resolve("password").toString(), ORIGIN, 1L, 0, 1001L, "fixture-key", key.toString());
        var dataSource = mock(javax.sql.DataSource.class);
        var sql = mock(org.apache.ibatis.session.SqlSessionFactory.class);
        var configuration = new com.baomidou.mybatisplus.core.MybatisConfiguration();
        configuration.setEnvironment(new org.apache.ibatis.mapping.Environment("fixture",
                new org.mybatis.spring.transaction.SpringManagedTransactionFactory(), dataSource));
        when(sql.getConfiguration()).thenReturn(configuration);
        var store = mock(top.egon.cola.component.outbox.store.OutboxStore.class);
        try (var context = PermissionIdentityBootstrapCli.context(input, OPERATION)) {
            context.addBeanFactoryPostProcessor(factory -> {
                factory.registerSingleton("dataSource", dataSource);
                factory.registerSingleton("sqlSessionFactory", sql);
                factory.registerSingleton("outboxStore", store);
                // The JDBC factory is a fixture; its interceptor contract is covered by the Common component suite.
                factory.registerSingleton("egonColaMybatisPlusContractValidator", mock(
                        top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusContractValidator.class));
            });
            context.refresh();
            assertThat(context.getBean(OAuthClientService.class)).isNotNull();
            assertThat(context.getBean(ResourceServerService.class)).isNotNull();
            assertThat(context.getBean(top.egon.cola.component.outbox.api.TransactionalOutbox.class)).isNotNull();
            assertThat(context.getBean(org.springframework.jdbc.datasource.DataSourceTransactionManager.class).getDataSource()).isSameAs(dataSource);
            assertThat(context.getBean(top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure.class).dataSource()).isSameAs(dataSource);
            assertThat(context.getBeansOfType(org.springframework.boot.ApplicationRunner.class)).isEmpty();
            assertThat(context.getBeansOfType(org.springframework.scheduling.TaskScheduler.class)).isEmpty();
            assertThat(context.getBeansOfType(org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping.class)).isEmpty();
            org.mockito.Mockito.verify(dataSource, org.mockito.Mockito.never()).getConnection();
        }
    }
}
