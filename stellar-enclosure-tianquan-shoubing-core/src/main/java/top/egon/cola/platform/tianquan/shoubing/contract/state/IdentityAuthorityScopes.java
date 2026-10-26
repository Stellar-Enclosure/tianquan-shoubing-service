package top.egon.cola.platform.tianquan.shoubing.contract.state;

/** Dedicated SERVICE capabilities for the database authority's terminating endpoints. */
public final class IdentityAuthorityScopes {
    public static final String STATE_RESOLVE = "tianquan-shoubing:security-state:resolve";
    public static final String REFRESH_CONTEXT = "tianquan-shoubing:refresh-context:resolve";
    public static final String AUDIT_APPEND = "tianquan-shoubing:audit:append";

    private IdentityAuthorityScopes() { }
}
