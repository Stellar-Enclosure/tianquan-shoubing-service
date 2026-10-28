package top.egon.cola.platform.tianquan.shoubing.admin.token.dao;

import java.time.Instant;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface SubjectDeliveryReceiptMapper {
    int insertIfAbsent(@Param("id") long id, @Param("tenantId") long tenantId, @Param("eventId") String eventId,
            @Param("subject") String subject, @Param("sourceRevision") long sourceRevision,
            @Param("previousRevision") long previousRevision, @Param("payloadFingerprint") String payloadFingerprint,
            @Param("now") Instant now, @Param("actor") String actor);
}
