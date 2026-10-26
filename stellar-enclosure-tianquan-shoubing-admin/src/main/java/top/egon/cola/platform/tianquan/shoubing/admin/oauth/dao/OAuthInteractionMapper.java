package top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthInteractionPO;

@Mapper
public interface OAuthInteractionMapper extends EgonColaMapper<OAuthInteractionPO> {

    OAuthInteractionPO selectByKey(@Param("tenantId") Long tenantId, @Param("key") String key);

    OAuthInteractionPO selectByKeyForUpdate(@Param("tenantId") Long tenantId, @Param("key") String key);

    List<OAuthInteractionPO> selectRetainedBefore(@Param("tenantId") Long tenantId,
            @Param("now") Instant now, @Param("afterId") long afterId, @Param("limit") int limit);

    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthInteractionPO po,
            @Param("expectedVersion") long expectedVersion);
    int deleteRetained(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("now") Instant now, @Param("actor") String actor);
}
