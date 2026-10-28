package top.egon.cola.platform.tianquan.shoubing.admin.token.dao;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.component.common.mybatis.model.EgonColaModelValidationGroups;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthSecurityStatePO;

@Mapper
@Validated
public interface OAuthSecurityStateMapper extends EgonColaMapper<OAuthSecurityStatePO> {

    int advanceRealmIfSubjectAbsent(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("subject") String subject,
            @Param("revision") long revision, @Param("now") java.time.Instant now, @Param("actor") String actor);

    int fenceRealmIfSubjectAbsent(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("subject") String subject,
            @Param("now") java.time.Instant now, @Param("actor") String actor);

    int fenceRealmIfConsentInactive(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("clientPk") Long clientPk,
            @Param("subject") String subject, @Param("now") java.time.Instant now, @Param("actor") String actor);

    int fenceRealmIfAuthorizationAbsent(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("authorizationId") long authorizationId,
            @Param("now") Instant now, @Param("actor") String actor);

    int fenceRealmIfAuthorizationTokensInactive(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("authorizationId") long authorizationId,
            @Param("now") Instant now, @Param("actor") String actor);

    int fenceSubjectDelivery(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("subject") String subject,
            @Param("sourceRevision") long sourceRevision, @Param("previousRevision") long previousRevision,
            @Param("now") java.time.Instant now, @Param("actor") String actor);
    int fenceSubjectDeliveryDuplicate(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") Long expectedVersion, @Param("subject") String subject,
            @Param("sourceRevision") long sourceRevision, @Param("previousRevision") long previousRevision,
            @Param("eventId") String eventId, @Param("payloadFingerprint") String payloadFingerprint,
            @Param("now") java.time.Instant now, @Param("actor") String actor);

    int fenceSubjectAtLeast(@Param("tenantId") Long tenantId, @Param("id") Long id,
            @Param("expectedVersion") long expectedVersion, @Param("subject") String subject,
            @Param("sourceRevision") long sourceRevision, @Param("fingerprint") String fingerprint,
            @Param("now") java.time.Instant now, @Param("actor") String actor);

    List<OAuthSecurityStatePO> selectSnapshot(@Param("tenantId") Long tenantId,
            @Param("clientKey") String clientKey, @Param("subject") String subject);

    int fenceRealmWhenTokenAbsent(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("tokenDigest") String tokenDigest,
            @Param("now") Instant now, @Param("actor") String actor);

    int advanceRealmIfRevocationAbsent(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("targetType") OAuthSecurityTargetEnum targetType,
            @Param("targetKey") String targetKey, @Param("revision") long revision,
            @Param("now") Instant now, @Param("actor") String actor);

    @Validated(EgonColaModelValidationGroups.Query.class)
    OAuthSecurityStatePO selectByTarget(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Positive(groups = EgonColaModelValidationGroups.Query.class) Long tenantId,
            @Param("targetType") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            OAuthSecurityTargetEnum targetType,
            @Param("targetKey") @NotBlank(groups = EgonColaModelValidationGroups.Query.class)
            @Size(max = 128, groups = EgonColaModelValidationGroups.Query.class) String targetKey);

    @Validated(EgonColaModelValidationGroups.Query.class)
    OAuthSecurityStatePO selectByTargetForUpdate(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Positive(groups = EgonColaModelValidationGroups.Query.class) Long tenantId,
            @Param("targetType") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            OAuthSecurityTargetEnum targetType,
            @Param("targetKey") @NotBlank(groups = EgonColaModelValidationGroups.Query.class)
            @Size(max = 128, groups = EgonColaModelValidationGroups.Query.class) String targetKey);

    @Validated(EgonColaModelValidationGroups.Query.class)
    List<OAuthSecurityStatePO> selectByRevisionAfter(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Positive(groups = EgonColaModelValidationGroups.Query.class) Long tenantId,
            @Param("afterRevision") @PositiveOrZero(groups = EgonColaModelValidationGroups.Query.class)
            Long afterRevision,
            @Param("afterId") @PositiveOrZero(groups = EgonColaModelValidationGroups.Query.class) Long afterId,
            @Param("limit") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Min(value = 1, groups = EgonColaModelValidationGroups.Query.class)
            @Max(value = 500, groups = EgonColaModelValidationGroups.Query.class) Integer limit);

    @Validated(EgonColaModelValidationGroups.Query.class)
    OAuthSecurityStatePO selectActiveById(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Positive(groups = EgonColaModelValidationGroups.Query.class) Long tenantId,
            @Param("id") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Positive(groups = EgonColaModelValidationGroups.Query.class) Long id);

    @Validated(EgonColaModelValidationGroups.Query.class)
    List<OAuthSecurityStatePO> selectActiveByIds(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Positive(groups = EgonColaModelValidationGroups.Query.class) Long tenantId,
            @Param("ids") @NotNull(groups = EgonColaModelValidationGroups.Query.class)
            @Size(min = 1, max = 500, groups = EgonColaModelValidationGroups.Query.class)
            Collection<@NotNull(groups = EgonColaModelValidationGroups.Query.class)
                    @Positive(groups = EgonColaModelValidationGroups.Query.class) Long> ids);

    @Validated(EgonColaModelValidationGroups.Update.class)
    int updateExpectedVersion(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Update.class)
            @Positive(groups = EgonColaModelValidationGroups.Update.class) Long tenantId,
            @Param("po") @NotNull(groups = EgonColaModelValidationGroups.Update.class)
            @Valid OAuthSecurityStatePO entity,
            @Param("expectedVersion") @NotNull(groups = EgonColaModelValidationGroups.Update.class)
            @PositiveOrZero(groups = EgonColaModelValidationGroups.Update.class) Long expectedVersion);

    @Validated(EgonColaModelValidationGroups.Delete.class)
    int deleteVersionedById(
            @Param("tenantId") @NotNull(groups = EgonColaModelValidationGroups.Delete.class)
            @Positive(groups = EgonColaModelValidationGroups.Delete.class) Long tenantId,
            @Param("po") @NotNull(groups = EgonColaModelValidationGroups.Delete.class)
            @Valid OAuthSecurityStatePO entity,
            @Param("expectedVersion") @NotNull(groups = EgonColaModelValidationGroups.Delete.class)
            @PositiveOrZero(groups = EgonColaModelValidationGroups.Delete.class) Long expectedVersion);
}
