package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthBrowserInteractionComponent;

@RestController
@io.swagger.v3.oas.annotations.Hidden
@RequiredArgsConstructor
public class OAuthLogoutController {
    @Qualifier("oauthBrowserInteractionComponent") private final OAuthBrowserInteractionComponent interactions;

    @GetMapping(value = "/tenants/{tenantId:[1-9][0-9]{0,18}}/logout", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> form(HttpServletRequest request) {
        var interaction = interactions.require(request, false);
        if (!"LOGOUT".equals(interaction.getPurpose()) || !(request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken csrf)) {
            return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
        }
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Referrer-Policy", "no-referrer")
                .header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
                .body("<!doctype html><html><body><main><h1>Sign out of this SSO sign-in</h1><form method=\"post\" action=\""
                        + interactions.realm(request).getIssuer().getRawPath() + "/logout\"><input type=\"hidden\" name=\"_csrf\" value=\""
                        + csrf.getToken().replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;") + "\"><button type=\"submit\">Sign out</button></form></main></body></html>");
    }

    @PostMapping(value = "/tenants/{tenantId:[1-9][0-9]{0,18}}/logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (request.getQueryString() != null || request.getContentLengthLong() > 2048
                || !java.util.Set.of("_csrf").equals(request.getParameterMap().keySet()) || request.getParameterValues("_csrf").length != 1) {
            return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
        }
        String redirect = interactions.completeLogout(request, authentication);
        var realm = interactions.realm(request);
        for (String purpose : java.util.List.of("authn", "interaction", "csrf")) {
            OAuthBrowserInteractionComponent.setCookie(request, response, OAuthBrowserInteractionComponent.name(purpose, realm), "", Duration.ZERO);
        }
        return redirect == null ? ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build()
                : ResponseEntity.status(303).location(URI.create(redirect)).cacheControl(CacheControl.noStore()).build();
    }
}
