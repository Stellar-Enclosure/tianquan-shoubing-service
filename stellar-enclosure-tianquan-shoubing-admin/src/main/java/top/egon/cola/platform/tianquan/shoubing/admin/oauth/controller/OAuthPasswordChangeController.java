package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthBrowserInteractionComponent;

/** Only a short-lived PASSWORD_CHANGE interaction may reach this native form. */
@RestController
@io.swagger.v3.oas.annotations.Hidden
@RequiredArgsConstructor
public class OAuthPasswordChangeController {
    @Qualifier("oauthBrowserInteractionComponent") private final OAuthBrowserInteractionComponent interactions;

    @GetMapping(value = "/tenants/{tenantId:[1-9][0-9]{0,18}}/password-change", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> form(HttpServletRequest request) {
        var interaction = interactions.require(request, false);
        if (!"PASSWORD_CHANGE".equals(interaction.getPurpose()) || interaction.getRestrictedSubject() == null
                || !(request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken csrf)) {
            return ResponseEntity.notFound().cacheControl(CacheControl.noStore()).build();
        }
        String html = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Change password</title></head><body><main>"
                + "<h1>Change your password</h1><form method=\"post\"><label>Current password<input type=\"password\" name=\"old_password\" autocomplete=\"current-password\" required maxlength=\"1024\"></label>"
                + "<label>New password<input type=\"password\" name=\"new_password\" autocomplete=\"new-password\" required maxlength=\"1024\"></label>"
                + "<input type=\"hidden\" name=\"_csrf\" value=\"" + csrf.getToken().replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;")
                + "\"><button type=\"submit\">Change password and sign in</button></form></main></body></html>";
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Referrer-Policy", "no-referrer")
                .header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'").body(html);
    }

    @PostMapping(value = "/tenants/{tenantId:[1-9][0-9]{0,18}}/password-change", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> change(HttpServletRequest request) {
        if (request.getQueryString() != null || request.getContentLengthLong() > 16_384
                || !Set.of("old_password", "new_password", "_csrf").equals(request.getParameterMap().keySet())
                || request.getParameterMap().values().stream().anyMatch(values -> values.length != 1 || values[0] == null || values[0].isEmpty() || values[0].length() > 1024)) {
            return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
        }
        char[] oldPassword = request.getParameter("old_password").toCharArray();
        char[] newPassword = request.getParameter("new_password").toCharArray();
        try {
            String location = interactions.changeRequiredPassword(request, oldPassword, newPassword);
            return ResponseEntity.status(303).location(URI.create(location)).cacheControl(CacheControl.noStore()).build();
        } catch (top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityException rejected) {
            return ResponseEntity.status(400).cacheControl(CacheControl.noStore()).build();
        } finally { Arrays.fill(oldPassword, '\0'); Arrays.fill(newPassword, '\0'); }
    }
}
