package top.egon.cola.platform.tianquan.shoubing.contract.state;

/** Dedicated SERVICE capabilities for the database authority's terminating endpoints. */
public final class IdentityAuthorityScopes {
    public static final String STATE_RESOLVE = "tianquan-shoubing:security-state:resolve";
    public static final String REFRESH_CONTEXT = "tianquan-shoubing:refresh-context:resolve";
    public static final String AUDIT_APPEND = "tianquan-shoubing:audit:append";
    public static final String EXECUTION_GRANT_ISSUE = "tianquan-shoubing:execution-grant:issue";
    public static final String EXECUTION_GRANT_RESOLVE = "tianquan-shoubing:execution-grant:resolve";
    public static final String EXECUTION_GRANT_REVOKE = "tianquan-shoubing:execution-grant:revoke";
    public static final String SERVICE_EXECUTION_GRANT_ISSUE = "tianquan-shoubing:service-execution-grant:issue";
    public static final String SERVICE_EXECUTION_GRANT_RESOLVE = "tianquan-shoubing:service-execution-grant:resolve";
    public static final String SERVICE_EXECUTION_GRANT_REVOKE = "tianquan-shoubing:service-execution-grant:revoke";

    private IdentityAuthorityScopes() { }
}
