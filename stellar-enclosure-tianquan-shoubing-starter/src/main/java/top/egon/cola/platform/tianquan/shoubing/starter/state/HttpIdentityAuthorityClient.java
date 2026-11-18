package top.egon.cola.platform.tianquan.shoubing.starter.state;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.Map;
import java.util.LinkedHashMap;
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
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;

/** A fixed authority endpoint and fixed SERVICE tuple; create one instance per trusted application context. */
public final class HttpIdentityAuthorityClient implements IdentityAuthorityClient {

    private static final int MAX_RESPONSE = 64 * 1024;
    private final URI authorityBase;
    private final RestClient transport;
    private final ObjectMapper mapper;
    private final IdpServiceOAuth2Client serviceOAuth;
    private final IdpServiceTokenRequest serviceContext;
    private final IdpTransportBindingRegistry bindings;
    private final Map<Operation, ReferenceVO> references;
    private final Duration timeout;

    public HttpIdentityAuthorityClient(URI authorityBase, RestClient transport, ObjectMapper mapper,
            IdpServiceOAuth2Client serviceOAuth, IdpServiceTokenRequest boundServiceContext) {
        this(authorityBase, transport, mapper, serviceOAuth, boundServiceContext,
                IdpTransportBindingRegistry.empty(), Map.of(), Duration.ofSeconds(2));
    }

    public HttpIdentityAuthorityClient(URI authorityBase, RestClient transport, ObjectMapper mapper,
            IdpServiceOAuth2Client serviceOAuth, IdpServiceTokenRequest boundServiceContext,
            IdpTransportBindingRegistry bindings, Map<Operation, IdpTransportBindingProperties.Reference> references,
            Duration timeout) {
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
        this.bindings = Objects.requireNonNull(bindings, "bindings");
        this.references = references(references);
        if (timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("IDENTITY_AUTHORITY_TIMEOUT_INVALID");
        }
        this.timeout = timeout;
        // Validate configured authority capabilities at assembly time without obtaining a SERVICE token.
        if (serviceContext.scopes().contains(IdentityAuthorityScopes.STATE_RESOLVE)
                || this.references.containsKey(Operation.AUTHORITY_RESOLVE)) {
            target("internal/v1/identity/security-state:resolve", Operation.AUTHORITY_RESOLVE);
        }
        if (serviceContext.scopes().contains(IdentityAuthorityScopes.AUDIT_APPEND)
                || this.references.containsKey(Operation.AUTHORITY_AUDIT)) {
            target("internal/v1/identity/audit-events", Operation.AUTHORITY_AUDIT);
        }
    }

    public static RestClient boundedTransport(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("IDENTITY_AUTHORITY_TIMEOUT_INVALID");
        }
        var client = HttpClient.newBuilder().connectTimeout(timeout).proxy(ProxySelector.of(null))
                .followRedirects(HttpClient.Redirect.NEVER).build();
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
        var response = post("internal/v1/identity/security-state:resolve", Operation.AUTHORITY_RESOLVE,
                request, scopes, IdentitySecurityStateResponse.class);
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
        var receipt = post("internal/v1/identity/audit-events", Operation.AUTHORITY_AUDIT,
                event, Set.of(IdentityAuthorityScopes.AUDIT_APPEND), IdentityAuditReceipt.class);
        if (receipt == null || !"STORED".equals(receipt.outcome()) || receipt.confirmedAt() == null
                || !Objects.equals(receipt.eventId(), event.eventId())
                || !Objects.equals(receipt.eventFingerprint(), TokenUsageAuditFingerprint.of(event))
                || !Objects.equals(receipt.resource(), event.resource()) || receipt.receiptId() == null
                || !Objects.equals(receipt.sourceIssuer(), source.issuer()) || !Objects.equals(receipt.sourceClientId(), source.clientId())) {
            throw new AuthorityUnavailableException("IDENTITY_AUDIT_RECEIPT_INVALID");
        }
        return receipt;
    }

    private <T> T post(String path, Operation operation, Object body, Set<String> requiredScopes, Class<T> responseType) {
        if (!serviceContext.scopes().containsAll(requiredScopes)) {
            throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_SERVICE_CAPABILITY_MISSING");
        }
        var context = new IdpServiceTokenRequest(serviceContext.registrationId(), serviceContext.appId(), serviceContext.audience(),
                serviceContext.context(), serviceContext.tenantId(), requiredScopes);
        URI endpoint = target(path, operation);
        boolean managed = usesManagedTransport(operation);
        String issuer = managed ? serviceOAuth.authorizationKey(serviceContext).issuer() : null;
        byte[] payload;
        try { payload = mapper.writeValueAsBytes(body); }
        catch (com.fasterxml.jackson.core.JsonProcessingException invalid) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_REQUEST_INVALID"); }
        try {
            if (payload.length > 32 * 1024) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_REQUEST_TOO_LARGE"); }
            for (int attempt = 0; attempt < 2; attempt++) {
                String token = (managed ? serviceOAuth.authorizeBounded(context, issuer, timeout)
                        : serviceOAuth.authorize(context)).getTokenValue();
                if (token == null || token.length() > 16_384 || !token.matches("[A-Za-z0-9._~+/-]+=*")) {
                    throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_SERVICE_AUTHENTICATION_REJECTED");
                }
                Exchange<T> exchange = transport.post().uri(endpoint).contentType(MediaType.APPLICATION_JSON)
                        .headers(headers -> {
                            headers.setBearerAuth(token);
                            var trace = top.egon.cola.component.common.trace.TraceContext.capture();
                            if (trace.traceId() != null) trace.child().inject(headers::set);
                        }).body(payload).exchange((request, response) -> {
                            int status = response.getStatusCode().value();
                            if (status == 401) { return new Exchange<>(status, null); }
                            if (status != 200) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_HTTP_" + status); }
                            var contentTypes = response.getHeaders().get("Content-Type");
                            if (contentTypes == null || contentTypes.size() != 1 || !MediaType.APPLICATION_JSON.isCompatibleWith(
                                    MediaType.parseMediaType(contentTypes.getFirst()))) {
                                throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_RESPONSE_INVALID");
                            }
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
                if (managed) {
                    serviceOAuth.invalidateBounded(context, issuer, timeout);
                } else {
                    serviceOAuth.invalidate(context);
                }
            }
            throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_SERVICE_AUTHENTICATION_REJECTED");
        } catch (AuthorityUnavailableException failure) { throw failure; }
        catch (RuntimeException unavailable) { throw new AuthorityUnavailableException("IDENTITY_AUTHORITY_UNAVAILABLE"); }
        finally { Arrays.fill(payload, (byte) 0); }
    }

    private URI target(String path, Operation operation) {
        URI canonical = authorityBase.resolve(path);
        if (!usesManagedTransport(operation)) {
            return canonical;
        }
        URI issuer = URI.create(serviceOAuth.authorizationKey(serviceContext).issuer());
        ReferenceVO reference = references.get(operation);
        IdpTransportBindingVO selected = reference == null
                ? bindings.select(issuer, canonical, serviceContext.audience(), serviceContext.registrationId(), operation, "POST")
                        .orElseThrow(() -> new IllegalArgumentException("IDENTITY_AUTHORITY_TRANSPORT_INVALID"))
                : bindings.require(reference.bindingId(), reference.version(), issuer, canonical, serviceContext.audience(),
                        serviceContext.registrationId(), operation, "POST");
        if (selected.transport() != IdpTransportBindingVO.Transport.HTTP) {
            throw new IllegalArgumentException("IDENTITY_AUTHORITY_TRANSPORT_INVALID");
        }
        return selected.physicalUri();
    }

    private boolean usesManagedTransport(Operation operation) {
        return references.containsKey(operation) || bindings.hasBindings(serviceContext.registrationId(), operation);
    }

    private static Map<Operation, ReferenceVO> references(Map<Operation, IdpTransportBindingProperties.Reference> values) {
        if (values == null) {
            throw new IllegalArgumentException("IDENTITY_AUTHORITY_TRANSPORT_REFERENCES_INVALID");
        }
        Map<Operation, ReferenceVO> result = new LinkedHashMap<>();
        values.forEach((operation, reference) -> {
            if ((operation != Operation.AUTHORITY_RESOLVE && operation != Operation.AUTHORITY_AUDIT)
                    || reference == null || reference.getBindingId() == null
                    || reference.getBindingId().isBlank() || reference.getVersion() <= 0) {
                throw new IllegalArgumentException("IDENTITY_AUTHORITY_TRANSPORT_REFERENCES_INVALID");
            }
            result.put(operation, new ReferenceVO(reference.getBindingId(), reference.getVersion()));
        });
        return Map.copyOf(result);
    }

    private record ReferenceVO(String bindingId, long version) { }

    private record Exchange<T>(int status, T value) { }

    public static final class AuthorityUnavailableException extends RuntimeException {
        public AuthorityUnavailableException(String code) { super(code); }
    }
}
