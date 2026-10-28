package top.egon.cola.platform.tianquan.shoubing.admin.resource.dao;

import java.time.Instant;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface OAuthResourceFenceMapper {
    Long selectVersion(@Param("tenantId") long tenantId, @Param("id") long id);
    int fenceObserved(@Param("tenantId") long tenantId, @Param("id") long id, @Param("expectedVersion") long expectedVersion,
            @Param("resourceVersion") long resourceVersion, @Param("resourceServerId") String resourceServerId,
            @Param("now") Instant now, @Param("actor") String actor);
}
