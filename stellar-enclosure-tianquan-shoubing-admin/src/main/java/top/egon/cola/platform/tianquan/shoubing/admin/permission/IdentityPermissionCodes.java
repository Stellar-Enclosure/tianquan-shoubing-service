package top.egon.cola.platform.tianquan.shoubing.admin.permission;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.*;

/** Stable management permission meanings owned by the identity producer. */
@PermissionDefinition(code = IdentityPermissionCodes.AUDIT_READ, meaning = "Audit read", labelPage = "identity.permissions", labelKey = "permission.audit.read")
@PermissionDefinition(code = IdentityPermissionCodes.BOOTSTRAP_READ, meaning = "Bootstrap read", labelPage = "identity.permissions", labelKey = "permission.bootstrap.read")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_USER_CREATE, meaning = "Identity user create", labelPage = "identity.permissions", labelKey = "permission.identity.user.create")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_USER_PASSWORD_RESET, meaning = "Identity user password reset", labelPage = "identity.permissions", labelKey = "permission.identity.user.password.reset")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_USER_READ, meaning = "Identity user read", labelPage = "identity.permissions", labelKey = "permission.identity.user.read")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_USER_REVOKE_ALL, meaning = "Identity user revoke all", labelPage = "identity.permissions", labelKey = "permission.identity.user.revoke.all")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_USER_UPDATE, meaning = "Identity user update", labelPage = "identity.permissions", labelKey = "permission.identity.user.update")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_SELF_READ, meaning = "Identity self read", labelPage = "identity.permissions", labelKey = "permission.identity.self.read")
@PermissionDefinition(code = IdentityPermissionCodes.OAUTH_CLIENT_CREATE, meaning = "Oauth client create", labelPage = "identity.permissions", labelKey = "permission.oauth.client.create")
@PermissionDefinition(code = IdentityPermissionCodes.OAUTH_CLIENT_READ, meaning = "Oauth client read", labelPage = "identity.permissions", labelKey = "permission.oauth.client.read")
@PermissionDefinition(code = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE, meaning = "Oauth client update", labelPage = "identity.permissions", labelKey = "permission.oauth.client.update")
@PermissionDefinition(code = IdentityPermissionCodes.RESOURCE_SERVER_CREATE, meaning = "Resource server create", labelPage = "identity.permissions", labelKey = "permission.resource.server.create")
@PermissionDefinition(code = IdentityPermissionCodes.RESOURCE_SERVER_GRANT, meaning = "Resource server grant", labelPage = "identity.permissions", labelKey = "permission.resource.server.grant")
@PermissionDefinition(code = IdentityPermissionCodes.RESOURCE_SERVER_READ, meaning = "Resource server read", labelPage = "identity.permissions", labelKey = "permission.resource.server.read")
@PermissionDefinition(code = IdentityPermissionCodes.RESOURCE_SERVER_STATUS, meaning = "Resource server status", labelPage = "identity.permissions", labelKey = "permission.resource.server.status")
@PermissionDefinition(code = IdentityPermissionCodes.SIGNING_KEY_ACTIVATE, meaning = "Signing key activate", labelPage = "identity.permissions", labelKey = "permission.signing.key.activate")
@PermissionDefinition(code = IdentityPermissionCodes.SIGNING_KEY_PUBLISH, meaning = "Signing key publish", labelPage = "identity.permissions", labelKey = "permission.signing.key.publish")
@PermissionDefinition(code = IdentityPermissionCodes.SIGNING_KEY_READ, meaning = "Signing key read", labelPage = "identity.permissions", labelKey = "permission.signing.key.read")
@PermissionDefinition(code = IdentityPermissionCodes.SIGNING_KEY_RETIRE, meaning = "Signing key retire", labelPage = "identity.permissions", labelKey = "permission.signing.key.retire")
@PermissionDefinition(code = IdentityPermissionCodes.TENANT_MANAGE, meaning = "Tenant manage", labelPage = "identity.permissions", labelKey = "permission.tenant.manage")
@PermissionDefinition(code = IdentityPermissionCodes.TENANT_READ, meaning = "Tenant read", labelPage = "identity.permissions", labelKey = "permission.tenant.read")
@PermissionDefinition(code = IdentityPermissionCodes.IDENTITY_SELF_SESSION_REVOKE, meaning = "Revoke own device session", labelPage = "identity.permissions", labelKey = "permission.identity.self.session.revoke")
public final class IdentityPermissionCodes {
    public static final String AUDIT_READ = "tianquan-shoubing:audit:read";
    public static final String BOOTSTRAP_READ = "tianquan-shoubing:bootstrap:read";
    public static final String IDENTITY_USER_CREATE = "tianquan-shoubing:identity-user:create";
    public static final String IDENTITY_USER_PASSWORD_RESET = "tianquan-shoubing:identity-user:password-reset";
    public static final String IDENTITY_USER_READ = "tianquan-shoubing:identity-user:read";
    public static final String IDENTITY_USER_REVOKE_ALL = "tianquan-shoubing:identity-user:revoke-all";
    public static final String IDENTITY_USER_UPDATE = "tianquan-shoubing:identity-user:update";
    public static final String IDENTITY_SELF_SESSION_REVOKE = "tianquan-shoubing:identity:self:session-revoke";
    public static final String IDENTITY_SELF_READ = "tianquan-shoubing:identity:self:read";
    public static final String OAUTH_CLIENT_CREATE = "tianquan-shoubing:oauth-client:create";
    public static final String OAUTH_CLIENT_READ = "tianquan-shoubing:oauth-client:read";
    public static final String OAUTH_CLIENT_UPDATE = "tianquan-shoubing:oauth-client:update";
    public static final String RESOURCE_SERVER_CREATE = "tianquan-shoubing:resource-server:create";
    public static final String RESOURCE_SERVER_GRANT = "tianquan-shoubing:resource-server:grant";
    public static final String RESOURCE_SERVER_READ = "tianquan-shoubing:resource-server:read";
    public static final String RESOURCE_SERVER_STATUS = "tianquan-shoubing:resource-server:status";
    public static final String SIGNING_KEY_ACTIVATE = "tianquan-shoubing:signing-key:activate";
    public static final String SIGNING_KEY_PUBLISH = "tianquan-shoubing:signing-key:publish";
    public static final String SIGNING_KEY_READ = "tianquan-shoubing:signing-key:read";
    public static final String SIGNING_KEY_RETIRE = "tianquan-shoubing:signing-key:retire";
    public static final String TENANT_MANAGE = "tianquan-shoubing:tenant:manage";
    public static final String TENANT_READ = "tianquan-shoubing:tenant:read";

    private IdentityPermissionCodes() { }
}
