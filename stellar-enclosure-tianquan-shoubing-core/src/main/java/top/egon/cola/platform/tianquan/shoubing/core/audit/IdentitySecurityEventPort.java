package top.egon.cola.platform.tianquan.shoubing.core.audit;

public interface IdentitySecurityEventPort {

    void append(IdentitySecurityEvent event);

    /** Records an event in the current business-partition transaction for later platform audit delivery. */
    default void appendForTenant(long storagePartitionId, IdentitySecurityEvent event) {
        throw new UnsupportedOperationException("IDENTITY_TENANT_AUDIT_UNSUPPORTED");
    }
}
