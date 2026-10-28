package top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo;

import java.time.Instant;
import lombok.Data;

/** Durable directory-shard intent for one tenant's subject revocation. */
@Data
public class SubjectRevocationTaskBO {
    private Long id;
    private Long tenantId;
    private Long version;
    private String identitySub;
    private String targetTenantId;
    private Long sourceRevision;
    private Boolean subjectEnabled;
    private String reasonCode;
    private String status;
    private Instant nextAttemptAt;
    private Integer attemptCount;
    private String leaseOwner;
    private Instant leaseUntil;
}
