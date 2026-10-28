package top.egon.cola.platform.tianquan.shoubing.admin.token.dao;

import java.time.Instant;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO;

@Mapper
public interface SubjectRevocationTaskMapper {
    List<Long> selectHistoryPage(@Param("tenantId") long tenantId, @Param("subject") String subject,
            @Param("after") long after, @Param("limit") int limit);
    int fenceHistoryPage(@Param("tenantId") long tenantId, @Param("id") long realmStateId,
            @Param("expectedVersion") long expectedVersion, @Param("subject") String subject,
            @Param("after") long after, @Param("last") long last, @Param("tenants") List<Long> tenants,
            @Param("count") int count,
            @Param("now") Instant now, @Param("actor") String actor);
    int insertTask(@Param("task") SubjectRevocationTaskBO task, @Param("now") Instant now, @Param("actor") String actor);
    List<SubjectRevocationTaskBO> selectDue(@Param("tenantId") long tenantId, @Param("now") Instant now, @Param("limit") int limit);
    int claim(@Param("tenantId") long tenantId, @Param("task") SubjectRevocationTaskBO task,
            @Param("owner") String owner, @Param("until") Instant until, @Param("now") Instant now, @Param("actor") String actor);
    int complete(@Param("tenantId") long tenantId, @Param("task") SubjectRevocationTaskBO task,
            @Param("owner") String owner, @Param("now") Instant now, @Param("actor") String actor);
    int retry(@Param("tenantId") long tenantId, @Param("task") SubjectRevocationTaskBO task,
            @Param("owner") String owner, @Param("next") Instant next, @Param("now") Instant now, @Param("actor") String actor);
}
