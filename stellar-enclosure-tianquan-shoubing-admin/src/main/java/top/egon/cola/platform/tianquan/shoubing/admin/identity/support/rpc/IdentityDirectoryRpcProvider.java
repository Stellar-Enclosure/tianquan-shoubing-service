package top.egon.cola.platform.tianquan.shoubing.admin.identity.support.rpc;

import top.egon.cola.component.rpc.annotation.EgonRpcProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityUserDirectory;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantMembershipBO;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.service.TenantMembershipService;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.IdentityDirectoryRpc;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.BatchGetIdentityProfilesRequest;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.BatchGetIdentityProfilesResponse;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.GetTenantMembershipRequest;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.GetTenantMembershipResponse;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityProfile;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityStatus;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.MembershipStatus;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.TenantMembershipProfile;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.TenantStatus;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;

/**
 * Maps the Tianquan-Shoubing identity directory to the minimal read-only RPC projection consumed by RBAC.
 */
@EgonRpcProvider
public final class IdentityDirectoryRpcProvider
        implements IdentityDirectoryRpc {

    private static final int MIN_SUBJECTS = 1;
    private static final int MAX_SUBJECTS = 100;

    private final IdentityUserDirectory directory;
    private final TenantMembershipService memberships;
    private final java.time.Clock clock;
    private final top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent observations;

    public IdentityDirectoryRpcProvider(
            IdentityUserDirectory directory,
            TenantMembershipService memberships
    ) {
        this(directory, memberships, java.time.Clock.systemUTC(), null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public IdentityDirectoryRpcProvider(IdentityUserDirectory directory, TenantMembershipService memberships,
            @org.springframework.beans.factory.annotation.Qualifier("idpClock") java.time.Clock clock,
            top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent observations) {
        this.directory = Objects.requireNonNull(directory, "directory");
        this.memberships = Objects.requireNonNull(memberships, "memberships");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.observations = observations;
    }

    @Override
    public BatchGetIdentityProfilesResponse batchGetIdentityProfiles(
            BatchGetIdentityProfilesRequest request) {
        Objects.requireNonNull(request, "request");
        requireService(null);
        List<String> subjects = normalizedSubjects(request.getSubjectsList());
        LinkedHashMap<String, IdentityUser> users = new LinkedHashMap<>();
        for (IdentityUser user : Objects.requireNonNull(
                directory.list(), "directory.list()")) {
            users.putIfAbsent(user.id(), user);
        }

        BatchGetIdentityProfilesResponse.Builder response =
                BatchGetIdentityProfilesResponse.newBuilder();
        for (String subject : subjects) {
            IdentityUser user = users.get(subject);
            if (user == null) {
                response.addMissingSubjects(subject);
                continue;
            }
            response.addProfiles(IdentityProfile.newBuilder()
                    .setSubject(user.id())
                    .setUsername(user.username())
                    .setDisplayName(user.displayName())
                    .setStatus(user.status().name())
                    .setVersion(user.version())
                    .build());
        }
        return response.build();
    }

    @Override
    public GetTenantMembershipResponse getTenantMembership(
            GetTenantMembershipRequest request
    ) {
        Objects.requireNonNull(request, "request");
        String tenantId = tenantId(request.getTenantId());
        requireService(tenantId);
        String identitySub = identitySub(request.getIdentitySub());
        TenantMembershipService.TenantMembershipProfile profile;
        try {
            profile = memberships.resolve(identitySub, tenantId);
        } catch (IllegalStateException exception) {
            if (isNotFound(exception)) {
                throw new NoSuchElementException("tenant membership not found");
            }
            throw exception;
        }
        if (profile == null) {
            throw new NoSuchElementException("tenant membership not found");
        }
        if (!tenantId.equals(profile.tenantId())
                || !identitySub.equals(profile.identitySub())) {
            throw new IllegalStateException(
                    "tenant membership response is not bound to request"
            );
        }
        return GetTenantMembershipResponse.newBuilder()
                .setProfile(TenantMembershipProfile.newBuilder()
                        .setTenantId(profile.tenantId())
                        .setIdentitySub(profile.identitySub())
                        .setTenantStatus(tenantStatus(profile.tenantStatus()))
                        .setMembershipStatus(membershipStatus(
                                profile.membershipStatus()
                        ))
                        .setMembershipVersion(profile.membershipVersion())
                        .setIdentityStatus(identityStatus(
                                profile.identityStatus()
                        ))
                        .build())
                .build();
    }

    /** Identity authority terminates locally; this proof gate never calls the RBAC authority that consumes it. */
    private void requireService(String requestedTenant) {
        var principal = top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.currentPrincipalOrNull();
        var proof = top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.currentProofOrNull();
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (!(principal instanceof top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal service)
                || authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal() != principal
                || proof == null || !proof.equals(authentication.getDetails())
                || !proof.resource().equals(service.resourceUri()) || !service.expiresAt().isAfter(clock.instant())
                || service.scopeContext() != top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext.TENANT
                || service.tenantId() == null || !service.scopes().contains("identity:read")
                || requestedTenant != null && !requestedTenant.equals(service.tenantId())) {
            if (observations != null && observations.enabled()) {
                var marker = top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.currentAuthorizationObservationContext();
                boolean confirmed = proof == null ? observations.authenticationFailure()
                        : marker == null ? observations.authorizationDenied(proof) : marker.denyOnce(() -> observations.authorizationDenied(proof));
                if (!confirmed) throw new org.springframework.security.authentication.AuthenticationServiceException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
            }
            throw new org.springframework.security.access.AccessDeniedException("IDENTITY_DIRECTORY_SERVICE_REQUIRED");
        }
    }

    private List<String> normalizedSubjects(List<String> values) {
        if (values.size() < MIN_SUBJECTS || values.size() > MAX_SUBJECTS) {
            throw new IllegalArgumentException(
                    "subjects must contain between 1 and 100 values");
        }
        LinkedHashMap<String, Boolean> unique = new LinkedHashMap<>();
        for (String value : values) {
            if (value == null || value.isBlank()
                    || !value.equals(value.trim())) {
                throw new IllegalArgumentException(
                        "subjects must contain non-blank values");
            }
            if (unique.putIfAbsent(value, Boolean.TRUE) != null) {
                throw new IllegalArgumentException(
                        "subjects must not contain duplicates");
            }
        }
        return List.copyOf(unique.keySet());
    }

    private static String tenantId(String value) {
        String normalized = required(value, "tenantId");
        if (normalized.length() > 64
                || !normalized.chars().allMatch(Character::isDigit)) {
            throw new IllegalArgumentException("tenantId is invalid");
        }
        return normalized;
    }

    private static String identitySub(String value) {
        String normalized = required(value, "identitySub");
        if (normalized.length() > 64) {
            throw new IllegalArgumentException("identitySub is invalid");
        }
        return normalized;
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank() || !value.equals(value.trim())) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static boolean isNotFound(IllegalStateException exception) {
        String message = exception.getMessage();
        return "tenant not found".equals(message)
                || "identity user not found".equals(message)
                || "membership not found".equals(message);
    }

    private static TenantStatus tenantStatus(IdentityTenantBO.Status status) {
        return switch (Objects.requireNonNull(status, "tenantStatus")) {
            case INITIALIZING -> TenantStatus.TENANT_STATUS_INITIALIZING;
            case ACTIVE -> TenantStatus.TENANT_STATUS_ACTIVE;
            case SUSPENDED -> TenantStatus.TENANT_STATUS_SUSPENDED;
            case CLOSED -> TenantStatus.TENANT_STATUS_CLOSED;
        };
    }

    private static IdentityStatus identityStatus(IdentityUserStatus status) {
        return switch (Objects.requireNonNull(status, "identityStatus")) {
            case ACTIVE -> IdentityStatus.IDENTITY_STATUS_ACTIVE;
            case DISABLED -> IdentityStatus.IDENTITY_STATUS_DISABLED;
            case LOCKED -> IdentityStatus.IDENTITY_STATUS_LOCKED;
        };
    }

    private static MembershipStatus membershipStatus(
            IdentityTenantMembershipBO.Status status
    ) {
        return switch (Objects.requireNonNull(status, "membershipStatus")) {
            case ACTIVE -> MembershipStatus.MEMBERSHIP_STATUS_ACTIVE;
            case DISABLED -> MembershipStatus.MEMBERSHIP_STATUS_DISABLED;
        };
    }
}
