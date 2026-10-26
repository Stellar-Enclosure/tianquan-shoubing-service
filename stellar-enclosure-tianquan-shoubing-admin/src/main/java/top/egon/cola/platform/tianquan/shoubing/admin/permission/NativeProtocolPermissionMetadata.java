package top.egon.cola.platform.tianquan.shoubing.admin.permission;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;

/**
 * Compile-time descriptions of native protocol endpoints. This class is not a Spring bean or HTTP handler.
 * Native SAS filters, SQL browser interactions and the identity-authority chain own their authentication.
 */
public final class NativeProtocolPermissionMetadata {
    private NativeProtocolPermissionMetadata() { }

    @RequestMapping(path = {"/tenants/{tenantId}/.well-known/openid-configuration", "/platform/.well-known/openid-configuration"}, method = {RequestMethod.GET})
    @PermissionResource(key = "tianquan-shoubing.protocol.oidcDiscovery", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "oidcDiscovery", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void oidcDiscovery() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/.well-known/oauth-authorization-server/tenants/{tenantId}", "/.well-known/oauth-authorization-server/platform"}, method = {RequestMethod.GET})
    @PermissionResource(key = "tianquan-shoubing.protocol.oauthDiscovery", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "oauthDiscovery", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void oauthDiscovery() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/.well-known/jwks.json", "/platform/.well-known/jwks.json"}, method = {RequestMethod.GET})
    @PermissionResource(key = "tianquan-shoubing.protocol.jwks", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "jwks", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void jwks() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/oauth2/authorize"}, method = {RequestMethod.GET})
    @PermissionResource(key = "tianquan-shoubing.protocol.authorizationRequest", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "authorizationRequest", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void authorizationRequest() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/oauth2/authorize"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.authorizationConsent", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "authorizationConsent", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void authorizationConsent() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/oauth2/token", "/platform/oauth2/token"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.token", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "token", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void token() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/oauth2/revoke", "/platform/oauth2/revoke"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.revocation", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "revocation", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void revocation() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/userinfo"}, method = {RequestMethod.GET})
    @PermissionResource(key = "tianquan-shoubing.protocol.userInfo", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "userInfo", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER}, oauthScopes = {"openid"})
    public static void userInfo() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/login"}, method = {RequestMethod.GET, RequestMethod.HEAD})
    @PermissionResource(key = "tianquan-shoubing.protocol.loginPage", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "loginPage", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void loginPage() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/consent"}, method = {RequestMethod.GET, RequestMethod.HEAD})
    @PermissionResource(key = "tianquan-shoubing.protocol.consentPage", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "consentPage", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void consentPage() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/password-change"}, method = {RequestMethod.GET, RequestMethod.HEAD})
    @PermissionResource(key = "tianquan-shoubing.protocol.passwordChangePage", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "passwordChangePage", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void passwordChangePage() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/logout"}, method = {RequestMethod.GET, RequestMethod.HEAD})
    @PermissionResource(key = "tianquan-shoubing.protocol.logoutPage", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "logoutPage", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void logoutPage() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/login"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.login", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "login", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void login() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/password-change"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.passwordChange", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "passwordChange", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void passwordChange() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/logout"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.logout", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "logout", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER})
    public static void logout() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/oauth2/token"}, method = {RequestMethod.OPTIONS})
    @PermissionResource(key = "tianquan-shoubing.protocol.tokenPreflight", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "tokenPreflight", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void tokenPreflight() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/userinfo"}, method = {RequestMethod.OPTIONS})
    @PermissionResource(key = "tianquan-shoubing.protocol.userInfoPreflight", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "userInfoPreflight", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void userInfoPreflight() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/.well-known/openid-configuration"}, method = {RequestMethod.OPTIONS})
    @PermissionResource(key = "tianquan-shoubing.protocol.discoveryPreflight", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "discoveryPreflight", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void discoveryPreflight() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/tenants/{tenantId}/.well-known/jwks.json"}, method = {RequestMethod.OPTIONS})
    @PermissionResource(key = "tianquan-shoubing.protocol.jwksPreflight", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "jwksPreflight", access = ResourceAccess.PUBLIC,
            allowedPrincipals = {PermissionManifest.PrincipalType.USER, PermissionManifest.PrincipalType.SERVICE})
    public static void jwksPreflight() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/internal/v1/identity/security-state:resolve"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.securityState", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "securityState", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-shoubing:security-state:resolve"})
    public static void securityState() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = {"/internal/v1/identity/audit-events"}, method = {RequestMethod.POST})
    @PermissionResource(key = "tianquan-shoubing.protocol.auditAppend", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "auditAppend", access = ResourceAccess.INTERNAL,
            allowedPrincipals = {PermissionManifest.PrincipalType.SERVICE}, oauthScopes = {"tianquan-shoubing:audit:append"})
    public static void auditAppend() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = "/egon.tianquan.shoubing.v1.IdentityDirectoryService/BatchGetIdentityProfiles", method = RequestMethod.POST, consumes = "application/grpc")
    @PermissionResource(key = "tianquan-shoubing.protocol.identityProfilesRpc", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "identityProfilesRpc", access = ResourceAccess.INTERNAL,
            allowedPrincipals = PermissionManifest.PrincipalType.SERVICE, oauthScopes = "identity:read")
    public static void identityProfilesRpc() { throw new UnsupportedOperationException("metadata only"); }

    @RequestMapping(path = "/egon.tianquan.shoubing.v1.IdentityDirectoryService/GetTenantMembership", method = RequestMethod.POST, consumes = "application/grpc")
    @PermissionResource(key = "tianquan-shoubing.protocol.tenantMembershipRpc", type = ResourceType.API,
            labelPage = "identity.protocol", labelKey = "tenantMembershipRpc", access = ResourceAccess.INTERNAL,
            allowedPrincipals = PermissionManifest.PrincipalType.SERVICE, oauthScopes = "identity:read")
    public static void tenantMembershipRpc() { throw new UnsupportedOperationException("metadata only"); }

}
