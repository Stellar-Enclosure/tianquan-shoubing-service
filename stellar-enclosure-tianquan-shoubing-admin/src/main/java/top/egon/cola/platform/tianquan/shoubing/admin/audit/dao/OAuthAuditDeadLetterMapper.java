package top.egon.cola.platform.tianquan.shoubing.admin.audit.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditDeadLetterPO;

@Mapper
public interface OAuthAuditDeadLetterMapper extends EgonColaMapper<OAuthAuditDeadLetterPO> {

    OAuthAuditDeadLetterPO selectByKey(@Param("tenantId") Long tenantId, @Param("key") Long key);

    OAuthAuditDeadLetterPO selectByKeyForUpdate(@Param("tenantId") Long tenantId, @Param("key") Long key);

    List<OAuthAuditDeadLetterPO> selectRetainedBefore(@Param("tenantId") Long tenantId,
            @Param("now") Instant now, @Param("afterId") long afterId, @Param("limit") int limit);

    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthAuditDeadLetterPO po,
            @Param("expectedVersion") long expectedVersion);
    int deleteRetained(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("now") Instant now, @Param("actor") String actor);
}
