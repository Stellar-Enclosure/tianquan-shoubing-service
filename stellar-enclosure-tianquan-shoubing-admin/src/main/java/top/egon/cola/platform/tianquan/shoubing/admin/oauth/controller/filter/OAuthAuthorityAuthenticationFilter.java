package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.core.JsonParser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

/** Owner-local SERVICE authentication; no remote state/audit callback can recursively enter this chain. */
public final class OAuthAuthorityAuthenticationFilter extends OncePerRequestFilter {

    public static final String CALLER_ATTRIBUTE = OAuthAuthorityService.Caller.class.getName();
    public static final String GRANT_BODY_ATTRIBUTE = OAuthAuthorityAuthenticationFilter.class.getName() + ".grantBody";
    private static final int MAX_BODY = 32 * 1024;
    private final OAuthAuthorityService authority;
    private final ObjectMapper mapper;
    private final ObjectMapper grantMapper;

    public OAuthAuthorityAuthenticationFilter(OAuthAuthorityService authority, ObjectMapper mapper) {
        this.authority = authority;
        this.mapper = mapper;
        this.grantMapper = mapper.copy().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader("Cache-Control", "no-store");
        if (!"POST".equals(request.getMethod())) { failure(response, 405, "method_not_allowed"); return; }
        var headers = Collections.list(request.getHeaders("Authorization"));
        if (headers.size() != 1 || !headers.getFirst().startsWith("Bearer ")
                || headers.getFirst().length() > 16_391 || headers.getFirst().substring(7).contains(" ")) {
            failure(response, 401, "invalid_token"); return;
        }
        String path = request.getRequestURI().substring(request.getContextPath().length());
        String scope = scope(path);
        if (scope == null) { failure(response, 404, "not_found"); return; }
        Class<?> grantType = grantType(path);
        if (grantType != null) {
            try {
                if (Collections.list(request.getHeaders("Content-Type")).size() != 1 || request.getContentType() == null
                        || !MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(request.getContentType()))) {
                    failure(response, 415, "unsupported_media_type"); return;
                }
            } catch (IllegalArgumentException invalid) { failure(response, 415, "unsupported_media_type"); return; }
        }
        int maximum = grantType == null ? MAX_BODY : ExecutionGrantContract.MAX_REQUEST_BYTES;
        byte[] body = request.getInputStream().readNBytes(maximum + 1);
        if (body.length > maximum) { java.util.Arrays.fill(body, (byte) 0); failure(response, 413, "request_too_large"); return; }
        var previous = SecurityContextHolder.getContext();
        try {
            var caller = authority.authenticateService(headers.getFirst().substring(7), scope);
            if (grantType != null) {
                try { request.setAttribute(GRANT_BODY_ATTRIBUTE, grantBody(body, grantType)); }
                catch (IOException | RuntimeException invalid) { failure(response, 400, "invalid_request"); return; }
            }
            var authentication = new IdpAuthenticationToken(caller.principal(), caller.principal().scopes().stream()
                    .map(value -> new SimpleGrantedAuthority("SCOPE_" + value)).toList(), caller.realm().getIssuer());
            var context = SecurityContextHolder.createEmptyContext(); context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            request.setAttribute(CALLER_ATTRIBUTE, caller);
            chain.doFilter(new BodyRequest(request, grantType == null ? body : new byte[0]), response);
        } catch (OAuth2AuthenticationException rejected) {
            failure(response, "temporarily_unavailable".equals(rejected.getError().getErrorCode()) ? 503 : 401,
                    "temporarily_unavailable".equals(rejected.getError().getErrorCode()) ? "temporarily_unavailable" : "invalid_token");
        } catch (AccessDeniedException rejected) {
            failure(response, 403, "insufficient_scope");
        } catch (IllegalArgumentException rejected) {
            failure(response, 400, "invalid_request");
        } catch (org.springframework.dao.DataAccessException | IllegalStateException unavailable) {
            failure(response, 503, "temporarily_unavailable");
        } finally {
            request.removeAttribute(CALLER_ATTRIBUTE);
            request.removeAttribute(GRANT_BODY_ATTRIBUTE);
            SecurityContextHolder.setContext(previous);
            java.util.Arrays.fill(body, (byte) 0);
        }
    }

    private Object grantBody(byte[] body, Class<?> type) throws IOException {
        var value = grantMapper.readTree(body);
        if (value == null || !value.isObject()) throw new IllegalArgumentException("EXECUTION_GRANT_BODY_INVALID");
        if (type == ExecutionGrantContract.IssueRequest.class) {
            if (value.size() != 6 || !value.path("userToken").isTextual() || !value.path("purpose").isTextual()
                    || !value.path("intentId").isTextual() || !value.path("bindingSha256").isTextual()
                    || !value.path("sessionRequired").isBoolean()
                    || !(value.path("deadlineAt").isTextual() || value.path("deadlineAt").isNumber())) {
                throw new IllegalArgumentException("EXECUTION_GRANT_BODY_INVALID");
            }
        } else {
            var ticket = value.path("ticket");
            if (value.size() != (type == ExecutionGrantContract.ResolveRequest.class ? 1 : 2)
                    || !ticket.isObject() || ticket.size() != 2 || !ticket.path("grantId").isTextual()
                    || !ticket.path("ciphertext").isTextual()
                    || type == ExecutionGrantContract.RevokeRequest.class && !value.path("userToken").isTextual()) {
                throw new IllegalArgumentException("EXECUTION_GRANT_BODY_INVALID");
            }
        }
        return grantMapper.treeToValue(value, type);
    }

    private static String scope(String path) {
        return switch (path) {
            case "/internal/v1/identity/security-state:resolve" -> IdentityAuthorityScopes.STATE_RESOLVE;
            case "/internal/v1/identity/audit-events" -> IdentityAuthorityScopes.AUDIT_APPEND;
            case ExecutionGrantContract.ISSUE_PATH -> IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE;
            case ExecutionGrantContract.RESOLVE_PATH -> IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE;
            case ExecutionGrantContract.REVOKE_PATH -> IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE;
            default -> null;
        };
    }

    private static Class<?> grantType(String path) {
        return switch (path) {
            case ExecutionGrantContract.ISSUE_PATH -> ExecutionGrantContract.IssueRequest.class;
            case ExecutionGrantContract.RESOLVE_PATH -> ExecutionGrantContract.ResolveRequest.class;
            case ExecutionGrantContract.REVOKE_PATH -> ExecutionGrantContract.RevokeRequest.class;
            default -> null;
        };
    }

    private void failure(HttpServletResponse response, int status, String code) throws IOException {
        if (response.isCommitted()) { return; }
        response.setStatus(status); response.setContentType("application/json");
        if (status == 401) { response.setHeader("WWW-Authenticate", "Bearer"); }
        mapper.writeValue(response.getOutputStream(), Map.of("error", code, "error_description", "Request rejected"));
    }

    private static final class BodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;
        private BodyRequest(HttpServletRequest request, byte[] body) { super(request); this.body = body; }
        @Override public ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public int read() { return input.read(); }
                @Override public boolean isFinished() { return input.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener listener) { throw new IllegalStateException("Asynchronous authority bodies are not supported"); }
            };
        }
    }
}
