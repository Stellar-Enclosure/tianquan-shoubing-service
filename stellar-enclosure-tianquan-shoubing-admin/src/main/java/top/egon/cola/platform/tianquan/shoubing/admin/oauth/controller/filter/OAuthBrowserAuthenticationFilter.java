package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthenticationJwtService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthBrowserInteractionComponent;

/** Restores only a browser authentication JWT; it never persists a Spring SecurityContext between requests. */
@Component("oauthBrowserAuthenticationFilter")
@RequiredArgsConstructor
public class OAuthBrowserAuthenticationFilter extends OncePerRequestFilter {
    @Qualifier("oauthBrowserInteractionComponent") private final OAuthBrowserInteractionComponent interactions;
    @Qualifier("oauthAuthenticationJwtService") private final OAuthAuthenticationJwtService authentications;

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().matches("/tenants/[1-9][0-9]{0,18}/(?:login|consent|oauth2/authorize|logout|password-change)");
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO realm;
            try { realm = interactions.realm(request); }
            catch (OAuth2AuthenticationException unknown) {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND); response.setHeader("Cache-Control", "no-store"); return;
            }
            SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
            if ("GET".equals(request.getMethod()) && request.getRequestURI().endsWith("/oauth2/authorize")) {
                interactions.saveRequest(request, response);
            }
            boolean passwordChange = request.getRequestURI().endsWith("/password-change");
            boolean logout = request.getRequestURI().endsWith("/logout");
            String compact = OAuthBrowserInteractionComponent.cookie(request, OAuthBrowserInteractionComponent.name("authn", realm));
            org.springframework.security.authentication.UsernamePasswordAuthenticationToken authentication = null;
            if (compact != null && !passwordChange) {
                try { authentication = authentications.verify(realm, compact, interactions.bindingDigest(request)); }
                catch (OAuth2AuthenticationException rejected) {
                    OAuthBrowserInteractionComponent.setCookie(request, response, OAuthBrowserInteractionComponent.name("authn", realm), "", java.time.Duration.ZERO);
                    SecurityContextHolder.clearContext();
                }
            }
            if ((logout || request.getRequestURI().endsWith("/consent")) && authentication == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setHeader("Cache-Control", "no-store");
                return;
            }
            if (logout && "GET".equals(request.getMethod())) { interactions.beginLogout(request, response, authentication); }
            // Browser POST is validated by CsrfFilter before its SQL-bound login, consent or lifecycle handler.
            var interaction = "POST".equals(request.getMethod()) ? null : interactions.require(request, false);
            if (interaction != null) {
                String expectedPurpose = passwordChange ? "PASSWORD_CHANGE" : logout ? "LOGOUT" : "AUTHORIZATION";
                if (!expectedPurpose.equals(interaction.getPurpose())) { throw new OAuth2AuthenticationException("invalid_request"); }
            }
            if (authentication != null) {
                @SuppressWarnings("unchecked")
                var details = new HashMap<>((Map<String, Object>) authentication.getDetails());
                if (interaction != null && "AUTHENTICATED".equals(interaction.getState())
                        && interaction.getAuthenticationJtiDigest().equals(details.get(OAuthAuthenticationJwtService.AUTHENTICATION_DIGEST))) {
                    details.put("reauthenticatedRequest", interaction.getRequestDigest());
                    details.put("reauthenticationExpiresAt", interaction.getExpiresAt());
                }
                authentication.setDetails(details);
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
            }
            chain.doFilter(request, response);
        } catch (OAuth2AuthenticationException rejected) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setHeader("Cache-Control", "no-store");
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("Browser interaction rejected");
        } catch (org.springframework.dao.DataAccessException | IllegalStateException unavailable) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setHeader("Cache-Control", "no-store");
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("Request temporarily unavailable");
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
