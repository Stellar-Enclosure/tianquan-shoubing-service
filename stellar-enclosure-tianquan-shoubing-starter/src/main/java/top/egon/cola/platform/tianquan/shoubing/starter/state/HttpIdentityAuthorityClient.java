package top.egon.cola.platform.tianquan.shoubing.starter.state;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityStatePurpose;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;

/** A fixed authority endpoint and fixed SERVICE tuple; create one instance per trusted application context. */
public final class HttpIdentityAuthorityClient implements IdentityAuthorityClient {

    private static final int MAX_RESPONSE = 64 * 1024;
    private final URI authorityBase;
    private final RestClient transport;
    private final ObjectMapper mapper;
    private final IdpServiceOAuth2Client serviceOAuth;
    private final IdpServiceTokenRequest serviceContext;

    public HttpIdentityAuthorityClient(URI authorityBase, RestClient transport, ObjectMapper mapper,
            IdpServiceOAuth2Client serviceOAuth, IdpServiceTokenRequest boundServiceContext) {
        if (authorityBase == null || !"https".equalsIgnoreCase(authorityBase.getScheme())
                || authorityBase.getHost() == null || authorityBase.getUserInfo() != null
                || authorityBase.getQuery() != null || authorityBase.getFragment() != null
                || !authorityBase.normalize().equals(authorityBase)) {
            throw new IllegalArgumentException("IDENTITY_AUTHORITY_URI_INVALID");
        }
        this.authorityBase = URI.create(authorityBase.toASCIIString().replaceAll("/+$", "") + "/");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.serviceOAuth = Objects.requireNonNull(serviceOAuth, "serviceOAuth");
        this.serviceContext = Objects.requireNonNull(boundServiceContext, "boundServiceContext");
    }

    public static RestClient boundedTransport(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("IDENTITY_AUTHORITY_TIMEOUT_INVALID");
        }
        var client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
        var factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(timeout);
        return RestClient.builder().requestFactory(factory).build();
    }

    @Override
    public IdentitySecurityStateResponse resolve(IdentitySecurityStateRequest request) {
        Objects.requireNonNull(request, "request");
        Set<String> scopes = request.getPurpose() == IdentityStatePurpose.REFRESH_CONTEXT
                ? Set.of(IdentityAuthorityScopes.STATE_RESOLVE, IdentityAuthorityScopes.REFRESH_CONTEXT)
                : Set.of(IdentityAuthorityScopes.STATE_RESOLVE);
        var response = post("internal/v1/identity/security-state:resolve", request, scopes, IdentitySecurityStateResponse.class);
        if (response == null || response.getPurpose() != request.getPurpose() || (response.getReasonCode() == null || !response.getReasonCode().matches("[A-Z0-9_]{1,96}"))
                || response.isEligible() && (!Objects.equals(response.getIssuer(), serviceOAuth.authorizationKey(serviceContext).issuer())
                || !Objects.equals(response.getClientId(), request.getExpectedClientId())
                || request.getExpectedResource() == null || !request.getExpectedResource().toASCIIString().equals(response.getResource())
                || response.getAuthorizationId() == null || response.getSecurityVersion() == null
                || response.getSubject() == null || response.getSubject().isBlank() || response.getAuthorizationExpiresAt() == null)) {
            throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_RESPONSE_INVALID");
        }
        return response;
    }

    @Override
    public IdentityAuditReceipt appendAudit(TokenUsageAuditEvent event) {
        Objects.requireNonNull(event, "event");
        var source = serviceOAuth.authorizationKey(serviceContext);
        var receipt = post("internal/v1/identity/audit-events", event, Set.of(IdentityAuthorityScopes.AUDIT_APPEND), IdentityAuditReceipt.class);
        if (receipt == null || !"STORED".equals(receipt.outcome()) || receipt.confirmedAt() == null
                || !Objects.equals(receipt.eventId(), event.eventId())
                || !Objects.equals(receipt.eventFingerprint(), TokenUsageAuditFingerprint.of(event))
                || !Objects.equals(receipt.resource(), event.resource()) || receipt.receiptId() == null
                || !Objects.equals(receipt.sourceIssuer(), source.issuer()) || !Objects.equals(receipt.sourceClientId(), source.clientId())) {
            throw new AuthorityUnavailableException("IDENTITY_AUDIT_RECEIPT_INVALID");
        }
        return receipt;
    }

    private <T> T post(String path, Object body, Set<String> requiredScopes, Class<T> responseType) {
        if (!serviceContext.scopes().containsAll(requiredScopes)) {
            throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_SERVICE_CAPABILITY_MISSING");
        }
        var context = new IdpServiceTokenRequest(serviceContext.registrationId(), serviceContext.appId(), serviceContext.audience(),
                serviceContext.context(), serviceContext.tenantId(), requiredScopes);
        byte[] payload;
        try { payload = mapper.writeValueAsBytes(body); }
        catch (com.fasterxml.jackson.core.JsonProcessingException invalid) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_REQUEST_INVALID"); }
        try {
            if (payload.length > 32 * 1024) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_REQUEST_TOO_LARGE"); }
            for (int attempt = 0; attempt < 2; attempt++) {
                String token = serviceOAuth.authorize(context).getTokenValue();
                Exchange<T> exchange = transport.post().uri(authorityBase.resolve(path)).contentType(MediaType.APPLICATION_JSON)
                        .headers(headers -> {
                            headers.setBearerAuth(token);
                            var trace = top.egon.cola.component.common.trace.TraceContext.capture();
                            if (trace.traceId() != null) trace.child().inject(headers::set);
                        }).body(payload).exchange((request, response) -> {
                            int status = response.getStatusCode().value();
                            if (status == 401) { return new Exchange<>(status, null); }
                            if (status != 200) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_HTTP_" + status); }
                            byte[] bytes = response.getBody().readNBytes(MAX_RESPONSE + 1);
                            try {
                                if (bytes.length > MAX_RESPONSE) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_RESPONSE_TOO_LARGE"); }
                                return new Exchange<>(status, mapper.readerFor(responseType)
                                        .with(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                                        .with(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).readValue(bytes));
                            } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) {
                                throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_RESPONSE_INVALID");
                            } finally { Arrays.fill(bytes, (byte) 0); }
                        });
                if (exchange != null && exchange.status() == 200) { return exchange.value(); }
                serviceOAuth.invalidate(context);
            }
            throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_SERVICE_AUTHENTICATION_REJECTED");
        } catch (AuthorityUnavailableException failure) { throw failure; }
        catch (RuntimeException unavailable) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_UNAVAILABLE"); }
        finally { Arrays.fill(payload, (byte) 0); }
    }

    private record Exchange<T>(int status, T value) { }

    public static final class AuthorityUnavailableException extends RuntimeException {
        public AuthorityUnavailableException(String code) { super(code); }
    }
}
