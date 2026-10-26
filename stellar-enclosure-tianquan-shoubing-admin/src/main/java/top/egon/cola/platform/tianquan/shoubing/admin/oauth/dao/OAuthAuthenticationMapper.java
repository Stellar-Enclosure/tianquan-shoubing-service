package top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthAuthenticationPO;

@Mapper
public interface OAuthAuthenticationMapper extends EgonColaMapper<OAuthAuthenticationPO> {

    OAuthAuthenticationPO selectByKey(@Param("tenantId") Long tenantId, @Param("key") String key);

    OAuthAuthenticationPO selectByKeyForUpdate(@Param("tenantId") Long tenantId, @Param("key") String key);

    List<OAuthAuthenticationPO> selectRetainedBefore(@Param("tenantId") Long tenantId,
            @Param("now") Instant now, @Param("afterId") long afterId, @Param("limit") int limit);

    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthAuthenticationPO po,
            @Param("expectedVersion") long expectedVersion);

    List<OAuthAuthenticationPO> selectByBrowser(@Param("tenantId") Long tenantId,
            @Param("binding") String binding, @Param("afterId") long afterId, @Param("limit") int limit);
    int deleteRetained(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("now") Instant now, @Param("actor") String actor);
}
