package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthInteractionPO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface OAuthInteractionConverter extends BaseConverter<OAuthInteractionPO, OAuthInteractionBO> {

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "interactionId", source = "interactionId")
    @Mapping(target = "purpose", source = "purpose")
    @Mapping(target = "clientPk", source = "clientPk")
    @Mapping(target = "resourceUri", source = "resourceUri")
    @Mapping(target = "redirectUri", source = "redirectUri")
    @Mapping(target = "requestDigest", source = "requestDigest")
    @Mapping(target = "requestCiphertext", source = "requestCiphertext")
    @Mapping(target = "browserBindingDigest", source = "browserBindingDigest")
    @Mapping(target = "clientBrowserBindingDigest", source = "clientBrowserBindingDigest")
    @Mapping(target = "csrfDigest", source = "csrfDigest")
    @Mapping(target = "requestedScopes", source = "requestedScopes")
    @Mapping(target = "approvedScopes", source = "approvedScopes")
    @Mapping(target = "codeChallenge", source = "codeChallenge")
    @Mapping(target = "codeChallengeMethod", source = "codeChallengeMethod")
    @Mapping(target = "authenticationJtiDigest", source = "authenticationJtiDigest")
    @Mapping(target = "restrictedSubject", source = "restrictedSubject")
    @Mapping(target = "state", source = "state")
    @Mapping(target = "expiresAt", source = "expiresAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    @Mapping(target = "consumedAt", source = "consumedAt")
    @Mapping(target = "failureCode", source = "failureCode")
    OAuthInteractionBO toTarget(OAuthInteractionPO value);

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "interactionId", source = "interactionId")
    @Mapping(target = "purpose", source = "purpose")
    @Mapping(target = "clientPk", source = "clientPk")
    @Mapping(target = "resourceUri", source = "resourceUri")
    @Mapping(target = "redirectUri", source = "redirectUri")
    @Mapping(target = "requestDigest", source = "requestDigest")
    @Mapping(target = "requestCiphertext", source = "requestCiphertext")
    @Mapping(target = "browserBindingDigest", source = "browserBindingDigest")
    @Mapping(target = "clientBrowserBindingDigest", source = "clientBrowserBindingDigest")
    @Mapping(target = "csrfDigest", source = "csrfDigest")
    @Mapping(target = "requestedScopes", source = "requestedScopes")
    @Mapping(target = "approvedScopes", source = "approvedScopes")
    @Mapping(target = "codeChallenge", source = "codeChallenge")
    @Mapping(target = "codeChallengeMethod", source = "codeChallengeMethod")
    @Mapping(target = "authenticationJtiDigest", source = "authenticationJtiDigest")
    @Mapping(target = "restrictedSubject", source = "restrictedSubject")
    @Mapping(target = "state", source = "state")
    @Mapping(target = "expiresAt", source = "expiresAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    @Mapping(target = "consumedAt", source = "consumedAt")
    @Mapping(target = "failureCode", source = "failureCode")
    OAuthInteractionPO toSource(OAuthInteractionBO value);
}
