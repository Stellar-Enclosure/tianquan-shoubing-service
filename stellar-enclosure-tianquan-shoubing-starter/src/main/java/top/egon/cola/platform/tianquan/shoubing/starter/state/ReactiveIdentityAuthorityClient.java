package top.egon.cola.platform.tianquan.shoubing.starter.state;

import java.util.Objects;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;

/** The host supplies a bounded worker scheduler; the Netty event loop never performs JDBC/HTTP blocking work. */
public final class ReactiveIdentityAuthorityClient {
    private final IdentityAuthorityClient delegate;
    private final Scheduler scheduler;

    public ReactiveIdentityAuthorityClient(IdentityAuthorityClient delegate, Scheduler boundedScheduler) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.scheduler = Objects.requireNonNull(boundedScheduler, "boundedScheduler");
    }

    public Mono<IdentitySecurityStateResponse> resolve(IdentitySecurityStateRequest request) {
        return Mono.fromCallable(() -> Objects.requireNonNull(delegate.resolve(request), "IDENTITY_AUTHORITY_RESPONSE_INVALID")).subscribeOn(scheduler);
    }

    public Mono<IdentityAuditReceipt> appendAudit(TokenUsageAuditEvent event) {
        return Mono.fromCallable(() -> Objects.requireNonNull(delegate.appendAudit(event), "IDENTITY_AUDIT_RECEIPT_INVALID")).subscribeOn(scheduler);
    }
}
