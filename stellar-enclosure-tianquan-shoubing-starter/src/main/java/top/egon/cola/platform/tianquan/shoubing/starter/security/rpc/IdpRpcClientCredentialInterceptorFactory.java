package top.egon.cola.platform.tianquan.shoubing.starter.security.rpc;

import io.grpc.CallOptions;
import io.grpc.CallCredentials;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.ForwardingClientCallListener;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import jakarta.validation.Validator;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.RpcConsumerBindingProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.RpcConsumerModeEnum;
import top.egon.cola.platform.tianquan.shoubing.contract.IdpPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInterceptorFactory;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInvocation;
import top.egon.cola.component.rpc.context.invocation.RpcMetadataKeys;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;

import java.util.Objects;
import java.util.function.Supplier;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.IdpServiceAuthorizationException;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest.IdpServiceTokenRequestException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Selects a fixed local RPC credential strategy. USER relay remains request scoped; SERVICE
 * acquisition runs on the gRPC application executor and reuses the existing OAuth2 client cache.
 */
@Slf4j
@RequiredArgsConstructor(staticName = "createConfigured")
public final class IdpRpcClientCredentialInterceptorFactory
        implements RpcClientInterceptorFactory {

    private static final int MAX_CREDENTIAL_LENGTH = 8192;

    @Qualifier("idpServiceOAuth2Client") private final IdpServiceOAuth2Client serviceClient;
    @Qualifier("idpStarterProperties") private final IdpStarterProperties properties;
    @Qualifier("defaultValidator") private final Validator validator;

    /** Preserves the existing USER-relay-only entry point. */
    public IdpRpcClientCredentialInterceptorFactory() { this(null, new IdpStarterProperties(), null); }

    @PostConstruct
    public void validateConfiguration() {
        if (!configured()) { return; }
        new ValidationUtils(Objects.requireNonNull(validator, "defaultValidator")).validate(properties.getRpc());
        if (properties.getRpc().getConsumer().getBindings().values().stream().anyMatch(binding -> binding.getMode() == RpcConsumerModeEnum.SERVICE)
                && serviceClient == null) {
            throw new IllegalStateException("SERVICE RPC requires idpServiceOAuth2Client");
        }
    }

    /**
     * Captures the trusted request-scoped USER token for the current RPC invocation.
     *
     * @param invocation current RPC invocation
     * @return client interceptor adding at most one Bearer credential
     */
    @Override
    public ClientInterceptor create(RpcClientInvocation invocation) {
        Objects.requireNonNull(invocation, "invocation");
        if (!configured()) {
            if (invocation.target() != null) { throw new IllegalStateException("native RPC credential binding is unavailable"); }
            return userRelay(VerifiedUserTokenCarrier.currentOrNull());
        }
        validateConfiguration();
        RpcConsumerBindingProperties binding = properties.getRpc().getConsumer().getBindings().values().stream()
                .filter(candidate -> matches(candidate, invocation)).findFirst()
                .orElseThrow(() -> new IllegalStateException("RPC target binding is unavailable"));
        if (binding.getMode() == RpcConsumerModeEnum.USER_RELAY) {
            // A SERVICE callback must never borrow a servlet token left on a reused worker.
            String token = IdpRpcSecurityContext.currentPrincipalOrNull() == null
                    ? VerifiedUserTokenCarrier.currentOrNull() : IdpRpcSecurityContext.currentTokenOrNull();
            if (token == null) { throw new IllegalStateException("verified USER RPC credential is unavailable"); }
            final String authorization = bearer(token);
            return boundInterceptor(invocation, binding.getFullMethodName(), () -> authorization);
        }
        IdpPrincipal principal = IdpRpcSecurityContext.currentPrincipalOrNull();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null && authentication != null && authentication.isAuthenticated()
                && (authentication instanceof IdpAuthenticationToken || authentication.getDetails() instanceof TokenAuditProofBO)
                && authentication.getPrincipal() instanceof IdpPrincipal verified) {
            principal = verified;
        }
        String tenant = binding.getScopeContext() == ServiceTokenContext.TENANT && principal != null ? principal.tenantId() : null;
        String registration = binding.getScopeContext() == ServiceTokenContext.PLATFORM ? binding.getRegistrationId()
                : tenant == null ? null : binding.getTenantRegistrationIds().get(tenant);
        if (registration == null) { throw new IllegalStateException("RPC tenant registration is unavailable"); }
        final IdpServiceTokenRequest request = new IdpServiceTokenRequest(registration, binding.getAppId(), binding.getResourceUri(),
                binding.getScopeContext(), tenant, binding.getScopes());
        return boundInterceptor(invocation, binding.getFullMethodName(),
                () -> bearer(serviceClient.authorize(request).getTokenValue()));
    }

    private ClientInterceptor boundInterceptor(RpcClientInvocation invocation, String fullMethodName,
            Supplier<String> authorization) {
        final Context caller = Context.current();
        final String authority = invocation.target().authority();
        return new ClientInterceptor() {
            @Override public <RequestT, ResponseT> ClientCall<RequestT, ResponseT> interceptCall(
                    MethodDescriptor<RequestT, ResponseT> method, CallOptions options, Channel next) {
                if (options.getCredentials() != null) { throw new IllegalStateException("RPC call credentials already exist"); }
                if (!fullMethodName.equals(method.getFullMethodName())) { throw new IllegalStateException("RPC method binding does not match"); }
                if (!authority.equals(next.authority())
                        || options.getAuthority() != null && !authority.equals(options.getAuthority())) {
                    throw new IllegalStateException("RPC authority binding does not match");
                }
                Context.CancellableContext credentialsContext = caller.withCancellation();
                CallCredentials credentials = boundCredentials(authorization, authority, fullMethodName, credentialsContext);
                ClientCall<RequestT, ResponseT> delegate;
                try { delegate = next.newCall(method, options.withCallCredentials(credentials)); }
                catch (RuntimeException createFailure) { credentialsContext.cancel(createFailure); throw createFailure; }
                return new ForwardingClientCall.SimpleForwardingClientCall<>(delegate) {
                    @Override public void start(Listener<ResponseT> listener, Metadata headers) {
                        try {
                            RpcMetadataKeys.validateRequestHeaders(headers);
                            rejectExistingAuthorization(headers);
                            super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<>(listener) {
                                @Override public void onClose(Status status, Metadata trailers) {
                                    try { super.onClose(status, trailers); } finally { credentialsContext.cancel(null); }
                                }
                            }, headers);
                        } catch (RuntimeException startFailure) { credentialsContext.cancel(startFailure); throw startFailure; }
                    }
                    @Override public void cancel(String message, Throwable cause) {
                        credentialsContext.cancel(cause);
                        super.cancel(message, cause);
                    }
                };
            }
        };
    }

    private CallCredentials boundCredentials(Supplier<String> authorization, String authority, String fullMethodName,
            Context.CancellableContext context) {
        return new CallCredentials() {
            @Override public void applyRequestMetadata(RequestInfo info, Executor appExecutor, MetadataApplier applier) {
                // RequestInfo describes the final transport call, including per-call authority overrides.
                if (info == null || !authority.equals(info.getAuthority()) || info.getMethodDescriptor() == null
                        || !fullMethodName.equals(info.getMethodDescriptor().getFullMethodName())) {
                    applier.fail(Status.PERMISSION_DENIED.withDescription("RPC credential target does not match"));
                    return;
                }
                AtomicBoolean completed = new AtomicBoolean();
                Context.CancellationListener cancellation = new Context.CancellationListener() {
                    @Override public void cancelled(Context ignored) {
                        try {
                            if (completed.compareAndSet(false, true)) {
                                applier.fail(Status.CANCELLED.withDescription("RPC credential acquisition cancelled"));
                            }
                        } finally { context.removeListener(this); }
                    }
                };
                context.addListener(cancellation, Runnable::run);
                if (completed.get()) { context.removeListener(cancellation); return; }
                try {
                    appExecutor.execute(context.wrap(() -> {
                        try {
                            if (context.isCancelled()) { cancellation.cancelled(context); return; }
                            if (completed.get()) { return; }
                            String bearer = authorization.get();
                            Metadata metadata = new Metadata();
                            metadata.put(RpcMetadataKeys.AUTHORIZATION, bearer);
                            if (context.isCancelled()) { cancellation.cancelled(context); return; }
                            if (completed.compareAndSet(false, true)) { applier.apply(metadata); }
                        } catch (RuntimeException acquisitionFailure) {
                            if (completed.compareAndSet(false, true)) { applier.fail(credentialFailure(acquisitionFailure)); }
                        } finally { context.removeListener(cancellation); }
                    }));
                } catch (RuntimeException schedulingFailure) {
                    try {
                        if (completed.compareAndSet(false, true)) {
                            applier.fail(Status.UNAVAILABLE.withDescription("RPC credential acquisition unavailable"));
                        }
                    } finally { context.removeListener(cancellation); }
                }
            }
            @Override public void thisUsesUnstableApi() { }
        };
    }

    private Status credentialFailure(RuntimeException failure) {
        String code = failure instanceof IdpServiceAuthorizationException authorization ? authorization.errorCode()
                : failure instanceof OAuth2AuthorizationException authorization ? authorization.getError().getErrorCode() : null;
        if (failure instanceof IdpServiceTokenRequestException) {
            return Status.FAILED_PRECONDITION.withDescription("RPC credential configuration is invalid");
        }
        if (code == null) { return Status.UNAVAILABLE.withDescription("RPC credential acquisition unavailable"); }
        return switch (code) {
            case "invalid_client", "invalid_grant", "invalid_token", "unauthorized_client", "invalid_token_response" ->
                    Status.UNAUTHENTICATED.withDescription("RPC credential authentication rejected");
            case "invalid_scope", "access_denied", "insufficient_scope" ->
                    Status.PERMISSION_DENIED.withDescription("RPC credential authorization rejected");
            case "request_invalid", "registration_invalid", "registration_identity_unavailable", "app_id_mismatch",
                    "issuer_mismatch", "issuer_untrusted", "issuer_unconfigured", "issuer_context_mismatch",
                    "token_endpoint_invalid", "token_endpoint_origin_mismatch", "registration_uri_invalid", "audience_invalid", "transport_binding_required",
                    "transport_binding_invalid", "credential_version_unconfigured", "credential_version_regression" ->
                    Status.FAILED_PRECONDITION.withDescription("RPC credential configuration is invalid");
            default -> Status.UNAVAILABLE.withDescription("RPC credential acquisition unavailable");
        };
    }

    private boolean configured() {
        return properties != null && properties.getRpc().isEnabled() && properties.getRpc().getConsumer().isEnabled();
    }

    private boolean matches(RpcConsumerBindingProperties binding, RpcClientInvocation invocation) {
        var process = invocation.processIdentity();
        var target = invocation.target();
        return process != null && target != null && binding.getTransportBindingId() != null
                && binding.getTransportBindingId().equals(target.bindingId())
                && binding.getTransportBindingVersion() != null && binding.getTransportBindingVersion() == target.version()
                && target.methods().contains(invocation.fullMethodName())
                && binding.getServiceName().equals(invocation.serviceName()) && binding.getGroup().equals(invocation.group())
                && binding.getVersion().equals(invocation.version()) && binding.getFullMethodName().equals(invocation.fullMethodName())
                && binding.getProcessIdentity().get("applicationName").equals(process.applicationName())
                && binding.getProcessIdentity().get("env").equals(process.env());
    }

    private ClientInterceptor userRelay(String token) {
        String authorization = token == null ? null : bearer(token);
        return new ClientInterceptor() {
            @Override
            public <RequestT, ResponseT> ClientCall<RequestT, ResponseT>
                    interceptCall(
                            MethodDescriptor<RequestT, ResponseT> method,
                            CallOptions callOptions,
                            Channel next
                    ) {
                ClientCall<RequestT, ResponseT> delegate =
                        next.newCall(method, callOptions);
                return new ForwardingClientCall.SimpleForwardingClientCall<>(
                        delegate
                ) {
                    @Override
                    public void start(
                            Listener<ResponseT> responseListener,
                            Metadata headers
                    ) {
                        RpcMetadataKeys.validateRequestHeaders(headers);
                        if (authorization != null) {
                            rejectExistingAuthorization(headers);
                            headers.put(
                                    RpcMetadataKeys.AUTHORIZATION,
                                    authorization
                            );
                        }
                        super.start(responseListener, headers);
                    }
                };
            }
        };
    }

    private void rejectExistingAuthorization(Metadata headers) {
        Iterable<String> existing = headers.getAll(RpcMetadataKeys.AUTHORIZATION);
        if (existing != null && existing.iterator().hasNext()) { throw new IllegalStateException("authorization metadata already exists"); }
    }

    private String bearer(String token) {
        if (token.isBlank() || token.length() > MAX_CREDENTIAL_LENGTH) {
            throw new IllegalArgumentException("verified USER token is invalid");
        }
        for (int index = 0; index < token.length(); index++) {
            char value = token.charAt(index);
            if (value < 0x21 || value > 0x7e) {
                throw new IllegalArgumentException(
                        "verified USER token is invalid"
                );
            }
        }
        return "Bearer " + token;
    }
}
