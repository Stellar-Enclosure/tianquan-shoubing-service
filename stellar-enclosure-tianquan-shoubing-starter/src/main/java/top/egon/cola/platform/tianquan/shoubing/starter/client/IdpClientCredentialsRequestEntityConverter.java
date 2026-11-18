package top.egon.cola.platform.tianquan.shoubing.starter.client;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Builds the Tianquan-Shoubing client-credentials request without putting the Secret in the form body.
 *
 * <p>The Spring client provider supplies the registration; the facade binds the
 * request-specific resource, context, tenant and scopes through a short-lived
 * thread-local while the synchronous manager call is in progress.</p>
 */
@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class IdpClientCredentialsRequestEntityConverter
        implements Converter<OAuth2ClientCredentialsGrantRequest,
        RequestEntity<?>> {

    @NonNull
    @Qualifier("idpTransportBindingRegistry")
    private final IdpTransportBindingRegistry transportBindings;

    private final ThreadLocal<RequestParametersVO> requestParameters =
            new ThreadLocal<>();

    /** External HTTPS compatibility; an internal destination always requires an explicit binding. */
    public IdpClientCredentialsRequestEntityConverter() {
        this(IdpTransportBindingRegistry.empty());
    }

    /** Converts a grant using the parameters bound by the facade. */
    @Override
    public RequestEntity<?> convert(
            OAuth2ClientCredentialsGrantRequest request
    ) {
        RequestParametersVO parameters = requestParameters.get();
        return create(request, parameters);
    }

    /** Converts the registration credentials into the standard Basic header. */
    public HttpHeaders convertHeaders(
            OAuth2ClientCredentialsGrantRequest request
    ) {
        if (request == null) {
            throw new IllegalArgumentException("grant request is required");
        }
        var registration = request.getClientRegistration();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(
                registration.getClientId(),
                registration.getClientSecret(),
                StandardCharsets.UTF_8
        );
        return headers;
    }

    /** Converts the grant and bound dimensions into form parameters. */
    public MultiValueMap<String, String> convertParameters(
            OAuth2ClientCredentialsGrantRequest request
    ) {
        if (request == null) {
            throw new IllegalArgumentException("grant request is required");
        }
        return parameters(requestParameters.get());
    }

    /**
     * Converts a grant with explicit request dimensions.
     *
     * <p>This overload is also useful for contract tests and custom manager
     * integrations; it never changes the Spring registration Secret.</p>
     */
    public RequestEntity<?> convert(
            OAuth2ClientCredentialsGrantRequest request,
            URI resource,
            ServiceTokenContext context,
            String tenantId,
            Set<String> scopes
    ) {
        return create(
                request,
                new RequestParametersVO(resource, context, tenantId, scopes)
        );
    }

    /** Binds dimensions for one synchronous manager authorization call. */
    public void bind(
            URI resource,
            ServiceTokenContext context,
            String tenantId,
            Set<String> scopes
    ) {
        requestParameters.set(new RequestParametersVO(
                resource,
                context,
                tenantId,
                scopes
        ));
    }

    /** Clears the request-scoped dimensions after manager authorization. */
    public void clear() {
        requestParameters.remove();
    }

    /** Resolves a deployed operation tuple; callers cannot supply the physical URL. */
    Optional<IdpTransportBindingVO> selectTransport(ClientRegistration registration, URI resource) {
        try {
            if (registration == null) {
                throw new IllegalArgumentException("registration is required");
            }
            URI endpoint = canonicalHttps(registration.getProviderDetails().getTokenUri());
            canonicalHttps(resource == null ? null : resource.toASCIIString());
            String configuredIssuer = registration.getProviderDetails().getIssuerUri();
            if ((configuredIssuer == null || configuredIssuer.isBlank())
                    && !transportBindings.hasBindings(registration.getRegistrationId(), IdpTransportBindingVO.Operation.TOKEN)) {
                // The legacy external facade may obtain its canonical issuer from validated starter configuration.
                return Optional.empty();
            }
            URI issuer = canonicalHttps(configuredIssuer);
            if (!sameOrigin(issuer, endpoint)) {
                throw new IllegalArgumentException("canonical token origin mismatch");
            }
            return transportBindings.select(issuer, endpoint, resource, registration.getRegistrationId(),
                    IdpTransportBindingVO.Operation.TOKEN, HttpMethod.POST.name());
        } catch (IllegalArgumentException invalid) {
            throw new IdpServiceTokenRequest.IdpServiceTokenRequestException(
                    "OAuth token transport binding is invalid");
        }
    }

    private RequestEntity<?> create(
            OAuth2ClientCredentialsGrantRequest request,
            RequestParametersVO parameters
    ) {
        if (request == null) {
            throw new IllegalArgumentException("grant request is required");
        }
        var registration = request.getClientRegistration();
        MultiValueMap<String, String> body = parameters(parameters);
        URI tokenUri = selectTransport(registration, parameters.resource())
                .map(IdpTransportBindingVO::physicalUri)
                .orElseGet(() -> URI.create(registration.getProviderDetails().getTokenUri()));
        return new RequestEntity<MultiValueMap<String, String>>(
                body,
                convertHeaders(request),
                HttpMethod.POST,
                tokenUri
        );
    }

    private static MultiValueMap<String, String> parameters(
            RequestParametersVO parameters
    ) {
        if (parameters == null) {
            throw new IdpServiceTokenRequest.IdpServiceTokenRequestException(
                    "OAuth request parameters are required");
        }
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("resource", parameters.resource().toString());
        if (parameters.context() == ServiceTokenContext.TENANT) {
            body.add("tenant_id", parameters.tenantId());
        }
        body.add("scope", String.join(" ", parameters.scopes()));
        return body;
    }

    private static URI canonicalHttps(String value) {
        if (value == null) { throw new IllegalArgumentException("canonical URI is required"); }
        URI uri = URI.create(value);
        if (!uri.isAbsolute() || uri.isOpaque() || uri.getHost() == null
                || !"https".equals(uri.getScheme()) || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || uri.getPort() == 0 || uri.getPort() > 65535
                || !uri.normalize().equals(uri) || !uri.toASCIIString().equals(value)) {
            throw new IllegalArgumentException("canonical HTTPS URI is required");
        }
        return uri;
    }

    private static boolean sameOrigin(URI left, URI right) {
        return left.getScheme().equals(right.getScheme()) && left.getHost().equalsIgnoreCase(right.getHost())
                && (left.getPort() == -1 ? 443 : left.getPort()) == (right.getPort() == -1 ? 443 : right.getPort());
    }

    private record RequestParametersVO(
            URI resource,
            ServiceTokenContext context,
            String tenantId,
            Set<String> scopes
    ) {
        private RequestParametersVO {
            if (resource == null || context == null || scopes == null
                    || scopes.isEmpty()) {
                throw new IllegalArgumentException(
                        "OAuth request parameters are invalid"
                );
            }
            if (context == ServiceTokenContext.TENANT
                    && (tenantId == null || tenantId.isBlank())) {
                throw new IllegalArgumentException(
                        "tenantId is required for TENANT context"
                );
            }
            if (context == ServiceTokenContext.PLATFORM && tenantId != null) {
                throw new IllegalArgumentException(
                        "PLATFORM context cannot carry tenantId"
                );
            }
            scopes = Collections.unmodifiableSet(
                    new LinkedHashSet<>(new TreeSet<>(scopes)));
        }
    }
}
