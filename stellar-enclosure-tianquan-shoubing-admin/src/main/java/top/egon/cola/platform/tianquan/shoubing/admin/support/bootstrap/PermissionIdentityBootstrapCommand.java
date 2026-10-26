package top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap;

import java.net.URI;
import java.util.List;
import java.util.Set;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.dto.CreateOAuthClientDTO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto.CreateResourceServerDTO;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;

/** Explicit operator input; credentials are referenced through protected files only. */
public record PermissionIdentityBootstrapCommand(int schemaVersion, String operationId, String connectionFile,
        String credentialDirectory, String actorSub, List<Client> clients, List<Resource> resources, List<Grant> grants) {
    public record Client(URI issuer, CreateOAuthClientDTO definition) { }
    public record Resource(CreateResourceServerDTO definition, boolean enable) { }
    public record Grant(URI issuer, String clientId, String resourceServerId, ResourceGrantType grantType,
            String tenantId, Set<String> allowedScopes) { }
    public record Connection(String jdbcUrl, String databaseName, String databaseOid, String databaseOwner,
            String username, String passwordFile, URI publicOrigin, long platformStoragePartitionId, Integer idMachineId,
            long platformManagementTenantId, String keyId, String keyFile) { }
}
