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
    int deleteRetained(@Param("tenantId") Long tenantId, @Param("now") Instant now,
            @Param("limit") int limit, @Param("actor") String actor);
    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthDeviceSessionPO po,
            @Param("expectedVersion") long expectedVersion);
}
