package top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthDeviceSessionPO;

@Mapper
public interface OAuthDeviceSessionMapper extends EgonColaMapper<OAuthDeviceSessionPO> {
    OAuthDeviceSessionPO selectSession(@Param("tenantId") Long tenantId, @Param("id") long id);
    OAuthDeviceSessionPO selectByAuthentication(@Param("tenantId") Long tenantId,
            @Param("digest") String digest, @Param("clientPk") Long clientPk);
    List<OAuthDeviceSessionPO> selectLiveBySubject(@Param("tenantId") Long tenantId,
            @Param("subject") String subject, @Param("now") Instant now);
    int fenceLiveSnapshot(@Param("tenantId") Long tenantId, @Param("stateId") long stateId,
            @Param("expectedVersion") long expectedVersion, @Param("subject") String subject,
            @Param("now") Instant now, @Param("sessions") List<top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO> sessions,
            @Param("count") int count, @Param("actor") String actor);
    int fenceRevokedWithoutLiveAuthorizations(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("now") Instant now, @Param("actor") String actor);
    List<OAuthDeviceSessionPO> selectRetainedCandidates(@Param("tenantId") Long tenantId,
            @Param("cutoff") Instant cutoff, @Param("limit") int limit);
    int deleteVersionedById(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("cutoff") Instant cutoff,
            @Param("now") Instant now, @Param("actor") String actor);
    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthDeviceSessionPO po,
            @Param("expectedVersion") long expectedVersion);
}
