package top.egon.cola.platform.tianquan.shoubing.starter.execution;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.http.MediaType;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;

/** One explicitly configured tenant, issuer and SERVICE registration; no write is automatically replayed. */
public final class HttpExecutionGrantClient {
    private final URI baseUri;
    private final URI issuer;
    private final long tenantId;
    private final IdpServiceTokenRequest service;
    private final IdpServiceOAuth2Client serviceOAuth;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final Duration timeout;
    private final Clock clock;

    public HttpExecutionGrantClient(URI baseUri, URI issuer, IdpServiceTokenRequest service,
            IdpServiceOAuth2Client serviceOAuth, ObjectMapper mapper, Duration timeout) {
        this(baseUri, issuer, service, serviceOAuth, mapper, timeout,
                HttpClient.newBuilder().connectTimeout(requireTimeout(timeout)).followRedirects(HttpClient.Redirect.NEVER).build(),
                Clock.systemUTC());
    }

    HttpExecutionGrantClient(URI baseUri, URI issuer, IdpServiceTokenRequest service,
            IdpServiceOAuth2Client serviceOAuth, ObjectMapper mapper, Duration timeout, HttpClient http, Clock clock) {
        this.baseUri = base(baseUri);
        this.issuer = secureUri(issuer);
        this.service = Objects.requireNonNull(service, "service");
        this.serviceOAuth = Objects.requireNonNull(serviceOAuth, "serviceOAuth");
        this.mapper = Objects.requireNonNull(mapper, "mapper").copy()
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS);
        this.timeout = requireTimeout(timeout);
        this.http = Objects.requireNonNull(http, "http");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (http.followRedirects() != HttpClient.Redirect.NEVER || service.context() != ServiceTokenContext.TENANT
                || service.tenantId() == null || !service.tenantId().matches("[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("EXECUTION_GRANT_CLIENT_BINDING_INVALID");
        }
        try { tenantId = Long.parseLong(service.tenantId()); }
        catch (NumberFormatException invalid) { throw new IllegalArgumentException("EXECUTION_GRANT_CLIENT_BINDING_INVALID"); }
        requireIssuer(service);
    }

    public ExecutionGrantContract.Issued issue(ExecutionGrantContract.IssueRequest request) {
        Objects.requireNonNull(request, "request");
        var result = post(ExecutionGrantContract.ISSUE_PATH, request, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE,
                ExecutionGrantContract.Issued.class);
        if (!result.expiresAt().isAfter(clock.instant()) || result.expiresAt().isAfter(request.deadlineAt())) throw unavailable();
        return result;
    }

    public ExecutionGrantContract.Resolution resolve(ExecutionGrantContract.Ticket ticket) {
        Objects.requireNonNull(ticket, "ticket");
        var result = post(ExecutionGrantContract.RESOLVE_PATH, new ExecutionGrantContract.ResolveRequest(ticket),
                IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE, ExecutionGrantContract.Resolution.class);
        if (!result.grantId().equals(ticket.grantId()) || !result.issuer().equals(issuer.toASCIIString())
                || result.tenantId() != tenantId || !result.expiresAt().isAfter(clock.instant())
                || result.expiresAt().isAfter(result.intentDeadlineAt())) throw unavailable();
        return result;
    }

    public void revoke(ExecutionGrantContract.RevokeRequest request) {
        Objects.requireNonNull(request, "request");
        post(ExecutionGrantContract.REVOKE_PATH, request, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, Void.class);
    }

    private <T> T post(String path, Object requestBody, String requiredScope, Class<T> type) {
        if (!service.scopes().contains(requiredScope)) throw unavailable();
        var context = new IdpServiceTokenRequest(service.registrationId(), service.appId(), service.audience(),
                service.context(), service.tenantId(), Set.of(requiredScope));
        long started = System.nanoTime();
        String token;
        try { token = serviceOAuth.authorizeBounded(context, issuer.toASCIIString(), timeout).getTokenValue(); }
        catch (RuntimeException failure) { throw unavailable(); }
        if (token == null || token.length() > 16_384 || !token.matches("[A-Za-z0-9._~+/-]+=*")) throw unavailable();
        byte[] payload;
        try { payload = mapper.writeValueAsBytes(requestBody); }
        catch (com.fasterxml.jackson.core.JsonProcessingException | RuntimeException invalid) { throw unavailable(); }
        if (payload.length > ExecutionGrantContract.MAX_REQUEST_BYTES) {
            Arrays.fill(payload, (byte) 0); throw unavailable();
        }
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        byte[] responseBody = null;
        try {
            var target = baseUri.resolve(path.substring(1));
            var builder = HttpRequest.newBuilder(target).timeout(Duration.ofNanos(remaining(started))).header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json").header("Accept", "application/json")
                    .header("Cache-Control", "no-store");
            var trace = top.egon.cola.component.common.trace.TraceContext.capture();
            if (trace.traceId() != null) trace.child().inject(builder::header);
            var request = builder.POST(HttpRequest.BodyPublishers.ofByteArray(payload)).build();
            pending = http.sendAsync(request, info -> new BoundedBody(ExecutionGrantContract.MAX_RESPONSE_BYTES));
            HttpResponse<byte[]> response = pending.get(remaining(started), TimeUnit.NANOSECONDS);
            responseBody = response.body();
            if (responseBody == null) throw unavailable();
            int status = response.statusCode();
            if (status == 401) {
                serviceOAuth.invalidateBounded(context, issuer.toASCIIString(), Duration.ofNanos(remaining(started)));
                throw unavailable();
            }
            if (status == 403 && json(response) && denied(responseBody)) throw new ExecutionGrantDeniedException();
            if (type == Void.class) {
                if (status != 204 || responseBody.length != 0) throw unavailable();
                return null;
            }
            if (status != 200 || !json(response) || responseBody.length == 0) throw unavailable();
            try {
                T value = mapper.readValue(responseBody, type);
                if (value == null) throw unavailable();
                return value;
            } catch (java.io.IOException | IllegalArgumentException invalid) { throw unavailable(); }
        } catch (ExecutionGrantDeniedException | ExecutionGrantUnavailableException failure) {
            throw failure;
        } catch (InterruptedException interrupted) {
            if (pending != null) pending.cancel(true);
            Thread.currentThread().interrupt();
            throw unavailable();
        } catch (TimeoutException timeoutFailure) {
            if (pending != null) pending.cancel(true);
            throw unavailable();
        } catch (ExecutionException | RuntimeException failure) {
            throw unavailable();
        } finally {
            if (pending != null && !pending.isDone()) pending.cancel(true);
            Arrays.fill(payload, (byte) 0);
            if (responseBody != null) Arrays.fill(responseBody, (byte) 0);
        }
    }

    private long remaining(long started) {
        long elapsed = Math.max(0L, System.nanoTime() - started);
        long value = timeout.toNanos() - elapsed;
        if (value <= 0) throw unavailable();
        return value;
    }

    private boolean denied(byte[] body) {
        try {
            Map<?, ?> value = mapper.readValue(body, Map.class);
            return value.size() == 1 && "access_denied".equals(value.get("error"));
        } catch (java.io.IOException | RuntimeException invalid) { return false; }
    }

    private static boolean json(HttpResponse<?> response) {
        try {
            var values = response.headers().allValues("Content-Type");
            return values.size() == 1 && MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(values.getFirst()));
        } catch (IllegalArgumentException invalid) { return false; }
    }

    private void requireIssuer(IdpServiceTokenRequest context) {
        try {
            if (!issuer.toASCIIString().equals(serviceOAuth.authorizationKey(context).issuer())) throw unavailable();
        } catch (ExecutionGrantUnavailableException failure) { throw failure; }
        catch (RuntimeException invalid) { throw unavailable(); }
    }

    private static URI base(URI value) {
        URI checked = secureUri(value);
        return URI.create(checked.toASCIIString().replaceAll("/+$", "") + "/");
    }

    private static URI secureUri(URI value) {
        if (value == null || !"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null || value.getFragment() != null
                || !value.normalize().equals(value) || value.toASCIIString().length() > 2048) {
            throw new IllegalArgumentException("EXECUTION_GRANT_CLIENT_URI_INVALID");
        }
        return value;
    }

    private static Duration requireTimeout(Duration value) {
        if (value == null || value.isZero() || value.isNegative() || value.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("EXECUTION_GRANT_CLIENT_TIMEOUT_INVALID");
        }
        return value;
    }

    private static ExecutionGrantUnavailableException unavailable() { return new ExecutionGrantUnavailableException(); }

    /** Explicitly denied intent; callers must not treat it as an infrastructure retry. */
    public static final class ExecutionGrantDeniedException extends RuntimeException {
        public ExecutionGrantDeniedException() { super("EXECUTION_GRANT_DENIED"); }
    }

    /** Unknown outcome, malformed response or unavailable authority; contains no remote response or credential. */
    public static final class ExecutionGrantUnavailableException extends RuntimeException {
        public ExecutionGrantUnavailableException() { super("EXECUTION_GRANT_UNAVAILABLE"); }
    }

    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final byte[] buffer;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription subscription;
        private int size;

        private BoundedBody(int limit) { buffer = new byte[limit]; }
        @Override public CompletionStage<byte[]> getBody() { return result; }
        @Override public void onSubscribe(Flow.Subscription value) {
            if (subscription != null) { value.cancel(); return; }
            subscription = value; value.request(1);
        }
        @Override public void onNext(List<ByteBuffer> values) {
            for (ByteBuffer value : values) {
                int count = value.remaining();
                if (count > buffer.length - size) {
                    subscription.cancel(); Arrays.fill(buffer, (byte) 0);
                    result.completeExceptionally(new IllegalStateException("EXECUTION_GRANT_RESPONSE_TOO_LARGE")); return;
                }
                value.get(buffer, size, count); size += count;
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable failure) { Arrays.fill(buffer, (byte) 0); result.completeExceptionally(failure); }
        @Override public void onComplete() {
            byte[] body = Arrays.copyOf(buffer, size); Arrays.fill(buffer, (byte) 0); result.complete(body);
        }
    }
}
