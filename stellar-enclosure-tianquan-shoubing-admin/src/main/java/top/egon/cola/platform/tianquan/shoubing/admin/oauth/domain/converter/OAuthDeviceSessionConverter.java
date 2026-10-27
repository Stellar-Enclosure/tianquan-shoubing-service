package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthDeviceSessionPO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface OAuthDeviceSessionConverter extends BaseConverter<OAuthDeviceSessionPO, OAuthDeviceSessionBO> {

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "clientPk", source = "clientPk")
    @Mapping(target = "subject", source = "subject")
    @Mapping(target = "authenticationJtiDigest", source = "authenticationJtiDigest")
    @Mapping(target = "authenticatedAt", source = "authenticatedAt")
    @Mapping(target = "expiresAt", source = "expiresAt")
    @Mapping(target = "userAgent", source = "userAgent")
    @Mapping(target = "ipAddress", source = "ipAddress")
    @Mapping(target = "status", source = "status")
    @Mapping(target = "revokedAt", source = "revokedAt")
    @Mapping(target = "reasonCode", source = "reasonCode")
    OAuthDeviceSessionBO toTarget(OAuthDeviceSessionPO value);

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "clientPk", source = "clientPk")
    @Mapping(target = "subject", source = "subject")
    @Mapping(target = "authenticationJtiDigest", source = "authenticationJtiDigest")
    @Mapping(target = "authenticatedAt", source = "authenticatedAt")
    @Mapping(target = "expiresAt", source = "expiresAt")
    @Mapping(target = "userAgent", source = "userAgent")
    @Mapping(target = "ipAddress", source = "ipAddress")
    @Mapping(target = "status", source = "status")
    @Mapping(target = "revokedAt", source = "revokedAt")
    @Mapping(target = "reasonCode", source = "reasonCode")
    OAuthDeviceSessionPO toSource(OAuthDeviceSessionBO value);

}
