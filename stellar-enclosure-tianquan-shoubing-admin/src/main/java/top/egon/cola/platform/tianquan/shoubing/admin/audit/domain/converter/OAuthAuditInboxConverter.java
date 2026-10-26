package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import top.egon.cola.component.common.core.converter.BaseConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditInboxPO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditInboxBO;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface OAuthAuditInboxConverter extends BaseConverter<OAuthAuditInboxPO, OAuthAuditInboxBO> {

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "eventId", source = "eventId")
    @Mapping(target = "eventFingerprint", source = "eventFingerprint")
    @Mapping(target = "schemaVersion", source = "schemaVersion")
    @Mapping(target = "sourceClientPk", source = "sourceClientPk")
    @Mapping(target = "sourceIssuer", source = "sourceIssuer")
    @Mapping(target = "sourceResourceUri", source = "sourceResourceUri")
    @Mapping(target = "eventPayload", source = "eventPayload")
    @Mapping(target = "occurredAt", source = "occurredAt")
    @Mapping(target = "receivedAt", source = "receivedAt")
    @Mapping(target = "state", source = "state")
    @Mapping(target = "attemptCount", source = "attemptCount")
    @Mapping(target = "nextAttemptAt", source = "nextAttemptAt")
    @Mapping(target = "claimOwner", source = "claimOwner")
    @Mapping(target = "claimToken", source = "claimToken")
    @Mapping(target = "claimGeneration", source = "claimGeneration")
    @Mapping(target = "leaseUntil", source = "leaseUntil")
    @Mapping(target = "terminalAt", source = "terminalAt")
    @Mapping(target = "failureCode", source = "failureCode")
    @Mapping(target = "processingDeadline", source = "processingDeadline")
    @Mapping(target = "retainUntil", source = "retainUntil")
    OAuthAuditInboxBO toTarget(OAuthAuditInboxPO value);

    @Override
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "id", source = "id")
    @Mapping(target = "version", source = "version")
    @Mapping(target = "eventId", source = "eventId")
    @Mapping(target = "eventFingerprint", source = "eventFingerprint")
    @Mapping(target = "schemaVersion", source = "schemaVersion")
    @Mapping(target = "sourceClientPk", source = "sourceClientPk")
    @Mapping(target = "sourceIssuer", source = "sourceIssuer")
    @Mapping(target = "sourceResourceUri", source = "sourceResourceUri")
    @Mapping(target = "eventPayload", source = "eventPayload")
    @Mapping(target = "occurredAt", source = "occurredAt")
    @Mapping(target = "receivedAt", source = "receivedAt")
    @Mapping(target = "state", source = "state")
    @Mapping(target = "attemptCount", source = "attemptCount")
    @Mapping(target = "nextAttemptAt", source = "nextAttemptAt")
    @Mapping(target = "claimOwner", source = "claimOwner")
    @Mapping(target = "claimToken", source = "claimToken")
    @Mapping(target = "claimGeneration", source = "claimGeneration")
    @Mapping(target = "leaseUntil", source = "leaseUntil")
    @Mapping(target = "terminalAt", source = "terminalAt")
    @Mapping(target = "failureCode", source = "failureCode")
    @Mapping(target = "processingDeadline", source = "processingDeadline")
    @Mapping(target = "retainUntil", source = "retainUntil")
    OAuthAuditInboxPO toSource(OAuthAuditInboxBO value);
}
