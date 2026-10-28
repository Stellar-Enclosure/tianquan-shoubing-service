package top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao;

import java.time.Instant;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface PasswordChangeReceiptMapper {
    int insertIfAbsent(@Param("id") long id, @Param("tenantId") long tenantId, @Param("operationKey") String operationKey,
            @Param("subject") String subject, @Param("originTenantId") long originTenantId,
            @Param("now") Instant now, @Param("actor") String actor);
}
