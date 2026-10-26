package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditReceiptPO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditReceiptBO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface OAuthAuditReceiptConverter extends BaseConverter<OAuthAuditReceiptPO, OAuthAuditReceiptBO> {

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "receiptId", source = "receiptId")
    @Mapping(target = "inboxPk", source = "inboxPk")
    @Mapping(target = "eventId", source = "eventId")
    @Mapping(target = "eventFingerprint", source = "eventFingerprint")
    @Mapping(target = "sourceClientPk", source = "sourceClientPk")
    @Mapping(target = "sourceIssuer", source = "sourceIssuer")
    @Mapping(target = "sourceResourceUri", source = "sourceResourceUri")
    @Mapping(target = "outcome", source = "outcome")
    @Mapping(target = "auditPk", source = "auditPk")
    @Mapping(target = "confirmedAt", source = "confirmedAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    OAuthAuditReceiptBO toTarget(OAuthAuditReceiptPO value);

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "receiptId", source = "receiptId")
    @Mapping(target = "inboxPk", source = "inboxPk")
    @Mapping(target = "eventId", source = "eventId")
    @Mapping(target = "eventFingerprint", source = "eventFingerprint")
    @Mapping(target = "sourceClientPk", source = "sourceClientPk")
    @Mapping(target = "sourceIssuer", source = "sourceIssuer")
    @Mapping(target = "sourceResourceUri", source = "sourceResourceUri")
    @Mapping(target = "outcome", source = "outcome")
    @Mapping(target = "auditPk", source = "auditPk")
    @Mapping(target = "confirmedAt", source = "confirmedAt")
    @Mapping(target = "retainUntil", source = "retainUntil")
    OAuthAuditReceiptPO toSource(OAuthAuditReceiptBO value);
}
