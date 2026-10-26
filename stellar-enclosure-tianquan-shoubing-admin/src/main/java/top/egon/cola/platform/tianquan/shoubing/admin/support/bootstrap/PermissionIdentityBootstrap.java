package top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.validation.Validator;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.OAuthClientService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto.ResourceVersionDTO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto.UpsertClientResourceGrantDTO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.service.ResourceServerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;

/** One explicit transaction reuses native client/resource owners and their transactional Outbox. */
final class PermissionIdentityBootstrap {
    private final ObjectMapper mapper;
    private final Validator validator;
    private final TransactionTemplate transaction;
    private final TenantIssuerService issuers;
    private final OAuthRealmRepository realms;
    private final OAuthClientRepository clients;
    private final OAuthResourceRepository resources;
    private final OAuthAuditRepository audits;
    private final OAuthClientService clientService;
    private final ResourceServerService resourceService;
    private final OAuthSecurityProjectionComponent security;
    private final Clock clock;

    PermissionIdentityBootstrap(ObjectMapper mapper, Validator validator, PlatformTransactionManager transactions,
            TenantIssuerService issuers, OAuthRealmRepository realms, OAuthClientRepository clients,
            OAuthResourceRepository resources, OAuthAuditRepository audits, OAuthClientService clientService,
            ResourceServerService resourceService, OAuthSecurityProjectionComponent security, Clock clock) {
        this.mapper = mapper; this.validator = validator; this.transaction = new TransactionTemplate(transactions);
        this.issuers = issuers; this.realms = realms; this.clients = clients; this.resources = resources;
        this.audits = audits; this.clientService = clientService; this.resourceService = resourceService;
        this.security = security; this.clock = clock;
    }

    static void validate(PermissionIdentityBootstrapCommand command, Validator validator) {
        if (command == null || command.schemaVersion() != 1 || command.operationId() == null
                || !UUID.fromString(command.operationId()).toString().equals(command.operationId())
                || command.actorSub() == null || !command.actorSub().matches("[A-Za-z0-9._~-]{1,64}")
                || command.clients() == null || command.clients().isEmpty() || command.clients().size() > 16
                || command.resources() == null || command.resources().size() > 16
                || command.grants() == null || command.grants().size() > 32) { throw rejected(); }
        PermissionBootstrapFiles.path(command.connectionFile());
        PermissionBootstrapFiles.path(command.credentialDirectory());
        Set<String> clientKeys = new LinkedHashSet<>(), resourceIds = new LinkedHashSet<>(), grantKeys = new LinkedHashSet<>();
        for (var client : command.clients()) {
            if (client == null || client.issuer() == null || client.definition() == null
                    || !validator.validate(client.definition()).isEmpty()
                    || !clientKeys.add(clientKey(client.issuer(), client.definition().getClientId()))) { throw rejected(); }
        }
        for (var resource : command.resources()) {
            if (resource == null || resource.definition() == null || !validator.validate(resource.definition()).isEmpty()
                    || !resourceIds.add(resource.definition().resourceServerId())
                    || command.clients().stream().noneMatch(value -> value.issuer().getPath().equals("/platform")
                            && value.definition().getClientId().equals(resource.definition().managementClientId()))) { throw rejected(); }
        }
        for (var grant : command.grants()) {
            if (grant == null || grant.issuer() == null || grant.grantType() == null || grant.allowedScopes() == null
                    || grant.grantType() == top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType.USER_DELEGATION
                    || !clientKeys.contains(clientKey(grant.issuer(), grant.clientId())) || !resourceIds.contains(grant.resourceServerId())
                    || !grantKeys.add(clientKey(grant.issuer(), grant.clientId()) + "|" + grant.resourceServerId() + "|" + grant.grantType())
                    || !validator.validate(UpsertClientResourceGrantDTO.of(grant.grantType(), grant.tenantId(),
                            grant.allowedScopes(), 0L, null)).isEmpty()) { throw rejected(); }
        }
    }

    JsonNode execute(PermissionIdentityBootstrapCommand command, URI publicOrigin, String digest) {
        return execute(command, publicOrigin, digest, false);
    }

    JsonNode execute(PermissionIdentityBootstrapCommand command, URI publicOrigin, String digest, boolean requireCommitted) {
        validate(command, validator);
        Path directory;
        try { directory = PermissionBootstrapFiles.resolvedDirectory(PermissionBootstrapFiles.path(command.credentialDirectory())); }
        catch (IOException failure) { throw rejected(); }
        Path journal = directory.resolve(command.operationId() + ".pending.json");
        return transaction.execute(status -> {
            URI platformIssuer = URI.create(publicOrigin.toASCIIString().replaceAll("/$", "") + "/platform");
            TrustedRealmBO platform = issuers.resolveExactIssuer(platformIssuer);
            realms.findByRealmKeyForUpdate(platform).orElseThrow(PermissionIdentityBootstrap::conflict);
            String eventId = "permission-bootstrap-" + command.operationId();
            var committed = audits.findByEventId(platform, eventId);
            if (committed.isPresent()) {
                JsonNode receipt = committed.get().getPayload();
                if (!digest.equals(receipt.path("commandDigest").asText())
                        || !command.operationId().equals(receipt.path("operationId").asText())) { throw conflict(); }
                verifyCredentials(receipt, directory, true);
                return receipt.deepCopy();
            }
            if (requireCommitted) { throw conflict(); }
            Map<URI, TrustedRealmBO> trusted = new LinkedHashMap<>();
            trusted.put(platformIssuer, platform);
            command.clients().stream().map(PermissionIdentityBootstrapCommand.Client::issuer).distinct()
                    .sorted(java.util.Comparator.comparing(URI::toASCIIString)).forEach(issuer -> {
                        TrustedRealmBO realm = issuers.resolveExactIssuer(issuer);
                        realms.findByRealmKeyForUpdate(realm).orElseThrow(PermissionIdentityBootstrap::conflict);
                        if (!security.isIssuerReady(realm)) { throw new IllegalStateException("PERMISSION_BOOTSTRAP_REALM_NOT_READY"); }
                        trusted.put(issuer, realm);
                    });
            for (var client : command.clients()) {
                if (clients.findByClientId(trusted.get(client.issuer()), client.definition().getClientId()).isPresent()) { throw conflict(); }
            }
            for (var resource : command.resources()) {
                var value = resource.definition();
                if (resources.findByResourceServerId(platform, value.resourceServerId()).isPresent()
                        || resources.findByResourceUri(platform, URI.create(value.resourceUri())).isPresent()
                        || resources.findBySource(platform, value.bizCode(), value.appCode(), value.environment()).isPresent()) { throw conflict(); }
            }
            ObjectNode receipt = mapper.createObjectNode().put("schemaVersion", 1).put("operationId", command.operationId())
                    .put("commandDigest", digest).put("createdAt", clock.instant().toString());
            receipt.putArray("clients"); receipt.putArray("resources"); receipt.put("grantCount", command.grants().size());
            prepareJournal(journal, receipt, directory);
            for (var client : command.clients()) {
                if (client.definition().getPurpose() == OAuthClientPurposeEnum.SERVICE) {
                    createClient(client, trusted, platform, command, receipt, journal, directory);
                }
            }
            Map<String, Long> versions = new LinkedHashMap<>();
            for (var resource : command.resources()) {
                var created = resourceService.create(platform, resource.definition());
                if (resource.enable()) {
                    created = resourceService.enable(platform, created.getResourceServerId(), new ResourceVersionDTO(created.getVersion()));
                }
                versions.put(created.getResourceServerId(), created.getVersion());
                receipt.withArray("resources").addObject().put("resourceServerId", created.getResourceServerId())
                        .put("version", Long.toString(created.getVersion()));
            }
            for (var client : command.clients()) {
                if (client.definition().getPurpose() == OAuthClientPurposeEnum.USER) {
                    if (client.definition().getResourceUris().stream().anyMatch(uri -> command.resources().stream()
                            .noneMatch(resource -> resource.enable() && uri.equals(resource.definition().resourceUri())))) { throw rejected(); }
                    createClient(client, trusted, platform, command, receipt, journal, directory);
                }
            }
            for (var grant : command.grants()) {
                resourceService.putGrant(trusted.get(grant.issuer()), platform, grant.clientId(), grant.resourceServerId(),
                        UpsertClientResourceGrantDTO.of(grant.grantType(), grant.tenantId(), grant.allowedScopes(),
                                versions.get(grant.resourceServerId()), null));
            }
            if (receipt.toString().getBytes(StandardCharsets.UTF_8).length > 16384) { throw rejected(); }
            audits.save(platform, OAuthAuditBO.builder().eventId(eventId).eventType("IDENTITY_PERMISSION_BOOTSTRAP_COMMITTED")
                    .result("SUCCESS").reasonCode("PERMISSION_BOOTSTRAP_COMMITTED").traceId(command.operationId())
                    .occurredAt(clock.instant()).payload(receipt.deepCopy()).auditKind("IDENTITY").publicId(eventId)
                    .retainUntil(java.time.Instant.parse("9999-12-31T23:59:59Z"))
                    .actorSub(command.actorSub()).build(), 0L);
            return receipt;
        });
    }

    private void createClient(PermissionIdentityBootstrapCommand.Client input, Map<URI, TrustedRealmBO> trusted,
            TrustedRealmBO platform, PermissionIdentityBootstrapCommand command, ObjectNode receipt, Path journal, Path directory) {
        var created = clientService.create(trusted.get(input.issuer()), platform, input.definition(), command.actorSub());
        var persisted = clients.findByClientId(trusted.get(input.issuer()), created.getClientId()).orElseThrow(PermissionIdentityBootstrap::conflict);
        var item = receipt.withArray("clients").addObject().put("issuer", input.issuer().toASCIIString())
                .put("clientId", created.getClientId()).put("clientPk", Long.toString(persisted.getId()))
                .put("generation", Long.toString(persisted.getCredentialVersion()));
        if (created.getClientSecret() != null) {
            byte[] bytes = created.getClientSecret().getBytes(StandardCharsets.UTF_8);
            created.setClientSecret(null);
            try {
                String name = command.operationId() + "-" + PermissionBootstrapFiles.digest(
                        clientKey(input.issuer(), created.getClientId()).getBytes(StandardCharsets.UTF_8)).substring(0, 24) + ".credential";
                item.put("file", name).put("sha256", PermissionBootstrapFiles.digest(bytes));
                PermissionBootstrapFiles.replaceOwned(journal, mapper.writeValueAsBytes(receipt));
                PermissionBootstrapFiles.create(directory.resolve(name), bytes);
            } catch (IOException failure) { throw new IllegalStateException("PERMISSION_BOOTSTRAP_CREDENTIAL_WRITE_FAILED", failure); }
            finally { Arrays.fill(bytes, (byte) 0); }
        }
    }

    private void prepareJournal(Path journal, ObjectNode receipt, Path directory) {
        try {
            if (Files.exists(journal, LinkOption.NOFOLLOW_LINKS)) {
                JsonNode pending = mapper.readTree(PermissionBootstrapFiles.read(journal, 16384));
                if (!receipt.path("operationId").equals(pending.path("operationId"))
                        || !receipt.path("commandDigest").equals(pending.path("commandDigest"))) { throw conflict(); }
                verifyCredentials(pending, directory, false);
                for (JsonNode item : pending.path("clients")) {
                    if (item.has("file")) { Files.deleteIfExists(credentialPath(directory, pending, item)); }
                }
                PermissionBootstrapFiles.replaceOwned(journal, mapper.writeValueAsBytes(receipt));
            } else { PermissionBootstrapFiles.create(journal, mapper.writeValueAsBytes(receipt)); }
        } catch (IOException failure) { throw new IllegalStateException("PERMISSION_BOOTSTRAP_JOURNAL_UNAVAILABLE", failure); }
    }

    private void verifyCredentials(JsonNode receipt, Path directory, boolean committed) {
        for (JsonNode item : receipt.path("clients")) {
            if (committed) {
                var realm = issuers.resolveExactIssuer(URI.create(item.path("issuer").asText()));
                var current = clients.findByClientId(realm, item.path("clientId").asText()).orElseThrow(PermissionIdentityBootstrap::conflict);
                if (!Long.toString(current.getId()).equals(item.path("clientPk").asText())
                        || !Long.toString(current.getCredentialVersion()).equals(item.path("generation").asText())) { throw conflict(); }
            }
            if (item.has("file")) {
                Path file = credentialPath(directory, receipt, item);
                if (!committed && !Files.exists(file, LinkOption.NOFOLLOW_LINKS)) { continue; }
                byte[] bytes = null;
                try {
                    bytes = PermissionBootstrapFiles.read(file, 128);
                    if (!PermissionBootstrapFiles.digest(bytes).equals(item.path("sha256").asText())) { throw conflict(); }
                } catch (IOException failure) { throw new IllegalStateException("PERMISSION_BOOTSTRAP_CREDENTIAL_UNAVAILABLE", failure); }
                finally { if (bytes != null) { Arrays.fill(bytes, (byte) 0); } }
            }
        }
    }

    private static Path credentialPath(Path directory, JsonNode receipt, JsonNode item) {
        String name = item.path("file").asText();
        if (!name.matches("[0-9a-f-]{36}-[0-9a-f]{24}\\.credential")
                || !name.startsWith(receipt.path("operationId").asText() + "-")) { throw conflict(); }
        return directory.resolve(name);
    }

    private static String clientKey(URI issuer, String clientId) { return issuer.toASCIIString() + "|" + clientId; }
    private static IllegalArgumentException rejected() { return PermissionBootstrapFiles.rejected(); }
    private static IllegalStateException conflict() { return new IllegalStateException("PERMISSION_BOOTSTRAP_STATE_CONFLICT"); }
}
