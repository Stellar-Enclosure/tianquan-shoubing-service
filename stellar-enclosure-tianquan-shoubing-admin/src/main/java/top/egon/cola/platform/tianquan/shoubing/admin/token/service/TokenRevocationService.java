package top.egon.cola.platform.tianquan.shoubing.admin.token.service;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.OAuthClientRevokeCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.OAuthSubjectRevokeCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.RevokeOAuthTokenCommand;

@Validated
public interface TokenRevocationService {

    void revoke(
            @NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull @Valid RevokeOAuthTokenCommand command);

    /** Revokes a token already observed by the caller; replica absence must remain retryable. */
    void revokeKnown(
            @NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull @Valid RevokeOAuthTokenCommand command);

    void revokeSubject(@NotNull @Valid OAuthSubjectRevokeCommand command);

    void applySubjectTask(@NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO task);

    void revokeClient(
            @NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull @Valid OAuthClientRevokeCommand command);
}
