package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionGrantService;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;

import java.util.Map;

/** The authority filter authenticates SERVICE callers and parses these sensitive request bodies. */
@RestController
@io.swagger.v3.oas.annotations.Hidden
@ConditionalOnProperty(prefix = "egon.tianquan-shoubing.execution-grants", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
@Slf4j
public class OAuthExecutionGrantController {
    @Qualifier("oauthExecutionGrantService") private final OAuthExecutionGrantService grants;

    @PostMapping(ExecutionGrantContract.ISSUE_PATH)
    public ResponseEntity<ExecutionGrantContract.Issued> issue(HttpServletRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(grants.issue(
                OAuthAuthorityController.caller(request), body(request, ExecutionGrantContract.IssueRequest.class)));
    }

    @PostMapping(ExecutionGrantContract.RESOLVE_PATH)
    public ResponseEntity<ExecutionGrantContract.Resolution> resolve(HttpServletRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(grants.resolve(
                OAuthAuthorityController.caller(request), body(request, ExecutionGrantContract.ResolveRequest.class)));
    }

    @PostMapping(ExecutionGrantContract.REVOKE_PATH)
    public ResponseEntity<Void> revoke(HttpServletRequest request) {
        grants.revoke(OAuthAuthorityController.caller(request), body(request, ExecutionGrantContract.RevokeRequest.class));
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<Map<String, String>> rejected(OAuth2AuthenticationException exception) {
        return failure("temporarily_unavailable".equals(exception.getError().getErrorCode()) ? 503 : 403);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> denied() { return failure(403); }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> invalid() { return failure(400); }

    @ExceptionHandler({DataAccessException.class, IllegalStateException.class})
    public ResponseEntity<Map<String, String>> unavailable() { return failure(503); }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> failed(RuntimeException exception) {
        log.error("Execution grant request failed with {}", exception.getClass().getName());
        return failure(500);
    }

    private static <T> T body(HttpServletRequest request, Class<T> type) {
        Object body = request.getAttribute(OAuthAuthorityAuthenticationFilter.GRANT_BODY_ATTRIBUTE);
        if (!type.isInstance(body)) throw new IllegalArgumentException("EXECUTION_GRANT_BODY_REQUIRED");
        return type.cast(body);
    }

    private static ResponseEntity<Map<String, String>> failure(int status) {
        String code = switch (status) {
            case 400 -> "invalid_request";
            case 403 -> "access_denied";
            case 503 -> "temporarily_unavailable";
            default -> "internal_error";
        };
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(Map.of("error", code));
    }
}
