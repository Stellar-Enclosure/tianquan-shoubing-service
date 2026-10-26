package top.egon.cola.platform.tianquan.shoubing.admin.identity.support.rpc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityUserDirectory;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.service.TenantMembershipService;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.BatchGetIdentityProfilesRequest;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.BatchGetIdentityProfilesResponse;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.GetTenantMembershipRequest;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.GetTenantMembershipResponse;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.TenantMembershipProfile;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantMembershipBO;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityDirectoryRpcProviderTest {
    private static final java.net.URI RESOURCE=java.net.URI.create("https://api.example/identity");
    private io.grpc.Context current;
    private io.grpc.Context previous;
    @BeforeEach void verifiedService(){attach(service("10001",java.util.Set.of("identity:read")),true);}
    @AfterEach void clear(){if(current!=null)current.detach(previous);org.springframework.security.core.context.SecurityContextHolder.clearContext();}

    private top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal service(String tenant,java.util.Set<String> scopes) {
        var now=java.time.Instant.now();
        return new top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal("rbac",tenant,"rbac","401",RESOURCE,0,scopes,
                "xingyuan","tianquan-jianshen","test","credential",now.minusSeconds(10),now.plusSeconds(3600),"rbac-app",top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext.TENANT);
    }
    private void attach(top.egon.cola.platform.tianquan.shoubing.contract.IdpPrincipal principal,boolean verified) {
        if(current!=null)current.detach(previous);
        var proof=verified?new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO(
                java.net.URI.create("https://idp.example/tenants/10001"),RESOURCE,"a".repeat(64),"b".repeat(64),"c".repeat(64)):null;
        current=top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.with(principal,"verified-fixture",proof,null);
        previous=current.attach();
        var auth=new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken(principal);auth.setDetails(proof);
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test void missingProofUserIdentityWrongScopeAndForeignTenantFailBeforeDirectoryReads() {
        var directory=mock(IdentityUserDirectory.class);var memberships=mock(TenantMembershipService.class);
        var provider=new IdentityDirectoryRpcProvider(directory,memberships);
        var request=GetTenantMembershipRequest.newBuilder().setTenantId("10002").setIdentitySub("user").build();
        assertThatThrownBy(()->provider.getTenantMembership(request)).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        attach(service("10001",java.util.Set.of("identity:read")),false);
        assertThatThrownBy(()->provider.batchGetIdentityProfiles(BatchGetIdentityProfilesRequest.newBuilder().addSubjects("user").build()))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        attach(service("10001",java.util.Set.of("other:read")),true);
        assertThatThrownBy(()->provider.getTenantMembership(request.toBuilder().setTenantId("10001").build()))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        var now=java.time.Instant.now();
        attach(new top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal("user","10001","41",java.util.Set.of(RESOURCE.toString()),now.minusSeconds(10),now.plusSeconds(100),top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext.password()),true);
        assertThatThrownBy(()->provider.getTenantMembership(request.toBuilder().setTenantId("10001").build()))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        org.mockito.Mockito.verifyNoInteractions(directory,memberships);
    }

    @Test void strictNativeDenialNeedsASqlAuditReceipt() {
        var observations=mock(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent.class);
        when(observations.enabled()).thenReturn(true);
        var provider=new IdentityDirectoryRpcProvider(mock(IdentityUserDirectory.class),mock(TenantMembershipService.class),java.time.Clock.systemUTC(),observations);
        assertThatThrownBy(()->provider.getTenantMembership(GetTenantMembershipRequest.newBuilder().setTenantId("10002").setIdentitySub("user").build()))
                .isInstanceOf(org.springframework.security.authentication.AuthenticationServiceException.class).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
        org.mockito.Mockito.verify(observations).authorizationDenied(org.mockito.ArgumentMatchers.any());
    }


    @Test
    void returnsMinimalProfilesAndMissingSubjects() {
        IdentityUserDirectory directory = mock(IdentityUserDirectory.class);
        when(directory.list()).thenReturn(List.of(
                user("subject-a", "alice", "Alice", 4L),
                user("subject-b", "bob", "Bob", 7L)));

        IdentityDirectoryRpcProvider provider =
                new IdentityDirectoryRpcProvider(
                        directory,
                        mock(TenantMembershipService.class)
                );
        BatchGetIdentityProfilesResponse response = provider
                .batchGetIdentityProfiles(BatchGetIdentityProfilesRequest.newBuilder()
                        .addSubjects("subject-a")
                        .addSubjects("subject-missing")
                        .build());

        assertThat(response.getProfilesList()).hasSize(1);
        assertThat(response.getProfiles(0).getSubject()).isEqualTo("subject-a");
        assertThat(response.getProfiles(0).getUsername()).isEqualTo("alice");
        assertThat(response.getProfiles(0).getDisplayName()).isEqualTo("Alice");
        assertThat(response.getProfiles(0).getStatus()).isEqualTo("ACTIVE");
        assertThat(response.getProfiles(0).getVersion()).isEqualTo(4L);
        assertThat(response.getMissingSubjectsList())
                .containsExactly("subject-missing");
    }

    @Test
    void rejectsEmptyDuplicateAndOversizedBatches() {
        IdentityDirectoryRpcProvider provider =
                new IdentityDirectoryRpcProvider(
                        mock(IdentityUserDirectory.class),
                        mock(TenantMembershipService.class)
                );

        assertThatThrownBy(() -> provider.batchGetIdentityProfiles(
                BatchGetIdentityProfilesRequest.getDefaultInstance()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> provider.batchGetIdentityProfiles(
                BatchGetIdentityProfilesRequest.newBuilder()
                        .addSubjects("subject-a")
                        .addSubjects("subject-a")
                        .build()))
                .isInstanceOf(IllegalArgumentException.class);

        BatchGetIdentityProfilesRequest.Builder oversized =
                BatchGetIdentityProfilesRequest.newBuilder();
        for (int index = 0; index < 101; index++) {
            oversized.addSubjects("subject-" + index);
        }
        assertThatThrownBy(() -> provider.batchGetIdentityProfiles(
                oversized.build()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void returnsCompleteTenantMembershipFactsWithoutRbacIdentifiers() {
        IdentityUserDirectory directory = mock(IdentityUserDirectory.class);
        TenantMembershipService memberships = mock(TenantMembershipService.class);
        when(memberships.resolve("user-1", "10001")).thenReturn(
                new TenantMembershipService.TenantMembershipProfile(
                        "user-1",
                        "10001",
                        "Acme",
                        "Mario",
                        IdentityTenantBO.Status.ACTIVE,
                        IdentityUserStatus.ACTIVE,
                        IdentityTenantMembershipBO.Status.ACTIVE,
                        TenantMembershipPort.MembershipStatus.ACTIVE,
                        4L,
                        java.time.Instant.parse("2026-08-22T02:00:00Z")
                )
        );

        IdentityDirectoryRpcProvider provider =
                new IdentityDirectoryRpcProvider(directory, memberships);
        GetTenantMembershipResponse response = provider.getTenantMembership(
                GetTenantMembershipRequest.newBuilder()
                        .setTenantId("10001")
                        .setIdentitySub("user-1")
                        .build()
        );

        TenantMembershipProfile profile = response.getProfile();
        assertThat(profile.getTenantId()).isEqualTo("10001");
        assertThat(profile.getIdentitySub()).isEqualTo("user-1");
        assertThat(profile.getTenantStatus().name()).endsWith("ACTIVE");
        assertThat(profile.getIdentityStatus().name()).endsWith("ACTIVE");
        assertThat(profile.getMembershipStatus().name()).endsWith("ACTIVE");
        assertThat(profile.getMembershipVersion()).isEqualTo(4L);
        assertThat(profile.getSerializedSize()).isGreaterThan(0);
    }

    @Test
    void rejectsWildcardAndMapsMissingAuthorityToNotFound() {
        TenantMembershipService memberships = mock(TenantMembershipService.class);
        when(memberships.resolve("user-1", "10001"))
                .thenThrow(new IllegalStateException("membership not found"));
        IdentityDirectoryRpcProvider provider =
                new IdentityDirectoryRpcProvider(
                        mock(IdentityUserDirectory.class),
                        memberships
                );

        assertThatThrownBy(() -> provider.getTenantMembership(
                GetTenantMembershipRequest.newBuilder()
                        .setTenantId("*")
                        .setIdentitySub("user-1")
                        .build()
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> provider.getTenantMembership(
                GetTenantMembershipRequest.newBuilder()
                        .setTenantId("10001")
                        .setIdentitySub("user-1")
                        .build()
        )).isInstanceOf(java.util.NoSuchElementException.class);
    }

    private IdentityUser user(
            String subject,
            String username,
            String displayName,
            long version) {
        return new IdentityUser(
                subject,
                username,
                username,
                displayName,
                IdentityUserStatus.ACTIVE,
                0,
                null,
                null,
                version);
    }
}
