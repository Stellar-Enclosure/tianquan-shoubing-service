package top.egon.cola.platform.tianquan.shoubing.admin.audit.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.component.common.mybatis.extension.EgonColaMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditReceiptPO;

@Mapper
public interface OAuthAuditReceiptMapper extends EgonColaMapper<OAuthAuditReceiptPO> {

    OAuthAuditReceiptPO selectByKey(@Param("tenantId") Long tenantId, @Param("key") String key);

    OAuthAuditReceiptPO selectByKeyForUpdate(@Param("tenantId") Long tenantId, @Param("key") String key);

    List<OAuthAuditReceiptPO> selectRetainedBefore(@Param("tenantId") Long tenantId,
            @Param("now") Instant now, @Param("afterId") long afterId, @Param("limit") int limit);

    int updateExpectedVersion(@Param("tenantId") Long tenantId, @Param("po") OAuthAuditReceiptPO po,
            @Param("expectedVersion") long expectedVersion);
    int deleteRetained(@Param("tenantId") Long tenantId, @Param("id") long id,
            @Param("expectedVersion") long expectedVersion, @Param("now") Instant now, @Param("actor") String actor);
}
