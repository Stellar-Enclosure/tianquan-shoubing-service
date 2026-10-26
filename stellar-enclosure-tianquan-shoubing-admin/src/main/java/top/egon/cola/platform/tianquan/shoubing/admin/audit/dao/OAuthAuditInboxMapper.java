package top.egon.cola.platform.tianquan.shoubing.admin.audit.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditInboxPO;

@Mapper
public interface OAuthAuditInboxMapper extends EgonColaMapper<OAuthAuditInboxPO> {

    OAuthAuditInboxPO selectByKey(@Param("tenantId") Long tenantId, @Param("key") String key);

    OAuthAuditInboxPO selectByKeyForUpdate(@Param("tenantId") Long tenantId, @Param("key") String key);

    List<OAuthAuditInboxPO> selectRetainedBefore(@Param("tenantId") Long tenantId,
            @Param("now") Instant now, @Param("afterId") long afterId, @Param("limit") int limit);

    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthAuditInboxPO po,
            @Param("expectedVersion") long expectedVersion);

    List<OAuthAuditInboxPO> selectDue(@Param("tenantId") Long tenantId,
            @Param("now") Instant now, @Param("limit") int limit);
    int deleteRetained(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("now") Instant now, @Param("actor") String actor);
}
