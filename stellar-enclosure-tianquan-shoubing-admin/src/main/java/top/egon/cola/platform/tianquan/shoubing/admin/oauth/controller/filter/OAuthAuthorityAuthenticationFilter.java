package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.web.filter.OncePerRequestFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

/** Owner-local SERVICE authentication; no remote state/audit callback can recursively enter this chain. */
public final class OAuthAuthorityAuthenticationFilter extends OncePerRequestFilter {

    public static final String CALLER_ATTRIBUTE = OAuthAuthorityService.Caller.class.getName();
    private static final int MAX_BODY = 32 * 1024;
    private final OAuthAuthorityService authority;
    private final ObjectMapper mapper;

    public OAuthAuthorityAuthenticationFilter(OAuthAuthorityService authority, ObjectMapper mapper) {
        this.authority = authority;
        this.mapper = mapper;
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
        byte[] body = request.getInputStream().readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) { failure(response, 413, "request_too_large"); return; }
        var previous = SecurityContextHolder.getContext();
        try {
            String scope = request.getRequestURI().endsWith("/audit-events")
                    ? IdentityAuthorityScopes.AUDIT_APPEND : IdentityAuthorityScopes.STATE_RESOLVE;
            var caller = authority.authenticateService(headers.getFirst().substring(7), scope);
            var authentication = new IdpAuthenticationToken(caller.principal(), caller.principal().scopes().stream()
                    .map(value -> new SimpleGrantedAuthority("SCOPE_" + value)).toList(), caller.realm().getIssuer());
            var context = SecurityContextHolder.createEmptyContext(); context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            request.setAttribute(CALLER_ATTRIBUTE, caller);
            chain.doFilter(new BodyRequest(request, body), response);
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
            SecurityContextHolder.setContext(previous);
            java.util.Arrays.fill(body, (byte) 0);
        }
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
