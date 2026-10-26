package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditDeadLetterPO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditDeadLetterBO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface OAuthAuditDeadLetterConverter extends BaseConverter<OAuthAuditDeadLetterPO, OAuthAuditDeadLetterBO> {

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "inboxPk", source = "inboxPk")
    @Mapping(target = "eventId", source = "eventId")
    @Mapping(target = "eventFingerprint", source = "eventFingerprint")
    @Mapping(target = "failureCode", source = "failureCode")
    @Mapping(target = "attemptCount", source = "attemptCount")
    @Mapping(target = "firstReceivedAt", source = "firstReceivedAt")
    @Mapping(target = "terminalAt", source = "terminalAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    OAuthAuditDeadLetterBO toTarget(OAuthAuditDeadLetterPO value);

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "inboxPk", source = "inboxPk")
    @Mapping(target = "eventId", source = "eventId")
    @Mapping(target = "eventFingerprint", source = "eventFingerprint")
    @Mapping(target = "failureCode", source = "failureCode")
    @Mapping(target = "attemptCount", source = "attemptCount")
    @Mapping(target = "firstReceivedAt", source = "firstReceivedAt")
    @Mapping(target = "terminalAt", source = "terminalAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    OAuthAuditDeadLetterPO toSource(OAuthAuditDeadLetterBO value);
}
