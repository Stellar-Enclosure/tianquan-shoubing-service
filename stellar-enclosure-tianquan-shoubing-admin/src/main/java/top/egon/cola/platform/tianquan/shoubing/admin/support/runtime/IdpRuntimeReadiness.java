package top.egon.cola.platform.tianquan.shoubing.admin.support.runtime;

@FunctionalInterface
public interface IdpRuntimeReadiness {

    Status status();

    record Status(boolean oauthRuntimeReady, boolean outboxAndAuditReady) {
        public boolean ready() {
            return oauthRuntimeReady && outboxAndAuditReady;
        }
    }
}
