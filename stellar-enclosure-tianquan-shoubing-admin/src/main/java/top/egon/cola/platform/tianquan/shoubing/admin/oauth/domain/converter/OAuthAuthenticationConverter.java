package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthAuthenticationPO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface OAuthAuthenticationConverter extends BaseConverter<OAuthAuthenticationPO, OAuthAuthenticationBO> {

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "jtiDigest", source = "jtiDigest")
    @Mapping(target = "subject", source = "subject")
    @Mapping(target = "browserBindingDigest", source = "browserBindingDigest")
    @Mapping(target = "subjectGeneration", source = "subjectGeneration")
    @Mapping(target = "realmGeneration", source = "realmGeneration")
    @Mapping(target = "authenticatedAt", source = "authenticatedAt")
    @Mapping(target = "acr", source = "acr")
    @Mapping(target = "status", source = "status")
    @Mapping(target = "expiresAt", source = "expiresAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    @Mapping(target = "revokedAt", source = "revokedAt")
    @Mapping(target = "reasonCode", source = "reasonCode")
    OAuthAuthenticationBO toTarget(OAuthAuthenticationPO value);

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "jtiDigest", source = "jtiDigest")
    @Mapping(target = "subject", source = "subject")
    @Mapping(target = "browserBindingDigest", source = "browserBindingDigest")
    @Mapping(target = "subjectGeneration", source = "subjectGeneration")
    @Mapping(target = "realmGeneration", source = "realmGeneration")
    @Mapping(target = "authenticatedAt", source = "authenticatedAt")
    @Mapping(target = "acr", source = "acr")
    @Mapping(target = "status", source = "status")
    @Mapping(target = "expiresAt", source = "expiresAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    @Mapping(target = "revokedAt", source = "revokedAt")
    @Mapping(target = "reasonCode", source = "reasonCode")
    OAuthAuthenticationPO toSource(OAuthAuthenticationBO value);
}
