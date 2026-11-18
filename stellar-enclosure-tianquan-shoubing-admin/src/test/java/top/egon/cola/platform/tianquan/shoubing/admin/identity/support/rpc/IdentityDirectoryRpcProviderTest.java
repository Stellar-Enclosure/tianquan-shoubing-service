package top.egon.cola.platform.tianquan.shoubing.admin.identity.support.rpc;


import com.google.protobuf.Message;
import io.grpc.CallOptions;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.MetadataUtils;
import jakarta.validation.Validation;
import top.egon.cola.component.accessguard.store.LogicalQuotaAcquireCommand;
import top.egon.cola.component.accessguard.store.LogicalQuotaBackend;
import top.egon.cola.component.accessguard.store.LogicalQuotaDecisionVO;
import top.egon.cola.component.accessguard.store.RateLimitDecision;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.component.rpc.config.EgonRpcProperties;
import top.egon.cola.component.rpc.consumer.interceptor.RpcConsumerClientInterceptor;
import top.egon.cola.component.rpc.context.identity.RpcProcessIdentity;
import top.egon.cola.component.rpc.context.invocation.RpcInvocationMetadata;
import top.egon.cola.component.rpc.context.invocation.RpcMetadataKeys;
import top.egon.cola.component.rpc.contract.validation.RpcContractValidator;
import top.egon.cola.component.rpc.provider.binding.RpcProviderBinding;
import top.egon.cola.component.rpc.provider.binding.RpcProviderMethodRegistry;
import top.egon.cola.component.rpc.provider.lifecycle.RpcProviderAvailabilityRegistry;
import top.egon.cola.component.rpc.provider.server.RpcProviderAdmissionComponent;
import top.egon.cola.component.rpc.provider.server.RpcProviderServerFactory;
import top.egon.cola.component.rpc.provider.server.RpcProviderServerInterceptor;
import top.egon.cola.component.rpc.provider.server.RpcServerServiceDefinitionFactory;
import top.egon.cola.platform.tianquan.shoubing.admin.support.runtime.IdpPlatformConfiguration;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.IdentityDirectoryRpc;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityDirectoryServiceGrpc;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpJwtVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcAdmissionIdentityResolver;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcBearerServerInterceptor;
import java.time.Duration;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
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
    private static final String BATCH = IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod().getFullMethodName();
    private static final String MEMBERSHIP = IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod().getFullMethodName();
    private static final URI ISSUER = URI.create("https://idp.example/tenants/10001");
    private io.grpc.Context current;
    private io.grpc.Context previous;
    @BeforeEach void verifiedService(){attach(service("10001",java.util.Set.of("identity:read")),true);}
    @AfterEach void clear(){if(current!=null)current.detach(previous);org.springframework.security.core.context.SecurityContextHolder.clearContext();}

    @Test
    void authenticatedServiceProofWithoutNativeMethodAdmissionCannotReadDirectory() {
        var directory = mock(IdentityUserDirectory.class);
        var memberships = mock(TenantMembershipService.class);
        when(directory.list()).thenReturn(List.of());
        var provider = new IdentityDirectoryRpcProvider(directory, memberships);
        assertThatThrownBy(() -> provider.batchGetIdentityProfiles(BatchGetIdentityProfilesRequest.newBuilder()
                .addSubjects("subject-a").build())).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        org.mockito.Mockito.verifyNoInteractions(directory, memberships);
    }

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
        assertThatThrownBy(()->authorized(MEMBERSHIP, () -> provider.getTenantMembership(GetTenantMembershipRequest.newBuilder().setTenantId("10002").setIdentitySub("user").build())))
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
        BatchGetIdentityProfilesResponse response = authorized(BATCH, () -> provider
                .batchGetIdentityProfiles(BatchGetIdentityProfilesRequest.newBuilder()
                        .addSubjects("subject-a")
                        .addSubjects("subject-missing")
                        .build()));

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

        authorized(BATCH, () -> {
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
        return null;
        });
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
        GetTenantMembershipResponse response = authorized(MEMBERSHIP, () -> provider.getTenantMembership(
                GetTenantMembershipRequest.newBuilder()
                        .setTenantId("10001")
                        .setIdentitySub("user-1")
                        .build()
        ));

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
        assertThatThrownBy(() -> authorized(MEMBERSHIP, () -> provider.getTenantMembership(
                GetTenantMembershipRequest.newBuilder()
                        .setTenantId("10001")
                        .setIdentitySub("user-1")
                        .build()
        ))).isInstanceOf(java.util.NoSuchElementException.class);
    }

    @Test
    void membershipAloneDeclaresTheApprovedRepeatedReadAndManagedBridgeIsExplicit() {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var contract = new RpcContractValidator(new ValidationUtils(factory.getValidator())).validate(IdentityDirectoryRpc.class);
            assertThat(contract.methods()).filteredOn(method -> method.fullMethodName().equals(MEMBERSHIP))
                    .singleElement().satisfies(method -> assertThat(method.idempotent()).isTrue());
            assertThat(contract.methods()).filteredOn(method -> method.fullMethodName().equals(BATCH))
                    .singleElement().satisfies(method -> assertThat(method.idempotent()).isFalse());
        }
        assertThat(IdentityDirectoryRpcProvider.class.getConstructors())
                .filteredOn(constructor -> constructor.isAnnotationPresent(org.springframework.beans.factory.annotation.Autowired.class))
                .singleElement().satisfies(constructor -> {
                    assertThat(constructor.getParameterTypes()).hasSize(5);
                    assertThat(constructor.getParameterTypes()[4]).isEqualTo(IdpRpcAdmissionIdentityResolver.class);
                    assertThat(constructor.getParameters()[4].getAnnotation(org.springframework.beans.factory.annotation.Qualifier.class).value())
                            .isEqualTo("idpRpcAdmissionIdentityResolver");
                });
    }

    @Test
    void disabledNativeProviderDoesNotRequireTheRuntimeIdentityBridgeDuringMigration() {
        var context = new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withUserConfiguration(IdentityDirectoryRpcProvider.class);
        context.withPropertyValues("egon.cola.component.rpc.provider.enabled=false").run(application -> {
            assertThat(application).hasNotFailed().doesNotHaveBean(IdentityDirectoryRpcProvider.class)
                    .doesNotHaveBean(IdpRpcAdmissionIdentityResolver.class);
        });
        context.run(application -> assertThat(application).hasNotFailed().doesNotHaveBean(IdentityDirectoryRpcProvider.class));
    }

    @Test
    void anotherApprovedMethodFrameCannotBeBorrowedForTheMembershipHandler() {
        var directory = mock(IdentityUserDirectory.class);
        var memberships = mock(TenantMembershipService.class);
        var provider = new IdentityDirectoryRpcProvider(directory, memberships);
        assertThatThrownBy(() -> authorized(BATCH, () -> provider.getTenantMembership(membershipRequest())))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        org.mockito.Mockito.verifyNoInteractions(directory, memberships);
    }

    @Test
    void realH2cProviderUsesOfficialServiceFrameAndProductionExceptionMapping() throws Exception {
        var quota = new CountingQuota();
        try (var f = new NativeFixture(quota, 10, true)) {
            var batch = f.invoke(IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod(),
                    BatchGetIdentityProfilesRequest.newBuilder().addSubjects("subject-a").build(), "batch-good", 1, "verified-fixture");
            assertThat(batch.getProfiles(0).getDisplayName()).isEqualTo("Alice");
            assertThat(f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(),
                    "membership-good", 1, "verified-fixture").getProfile().getMembershipVersion()).isEqualTo(4);
            var foreign = membershipRequest().toBuilder().setTenantId("10002").build();
            rejected(Status.Code.PERMISSION_DENIED, () -> f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    foreign, "foreign", 1, "verified-fixture"));
            org.mockito.Mockito.verify(f.memberships, org.mockito.Mockito.never()).resolve("user-1", "10002");
            org.mockito.Mockito.when(f.memberships.resolve("user-1", "10001")).thenThrow(new IllegalStateException("membership not found"));
            rejected(Status.Code.NOT_FOUND, () -> f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    membershipRequest(), "missing", 1, "verified-fixture"));
            rejected(Status.Code.INVALID_ARGUMENT, () -> f.invoke(IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod(),
                    BatchGetIdentityProfilesRequest.getDefaultInstance(), "empty-batch", 1, "verified-fixture"));
        }
    }

    @Test
    void realH2cAuthFailuresAndUnapprovedOrUnknownMethodsNeverEnterDomainOrQuota() throws Exception {
        var quota = new CountingQuota();
        try (var f = new NativeFixture(quota, 10, false)) {
            rejected(Status.Code.UNAUTHENTICATED, () -> f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    membershipRequest(), "no-token", 1, null));
            f.verification.set(new AccessTokenVerification.Valid<>(service("10001", Set.of("other:read")), Set.of("other:read"), proof(), ISSUER));
            rejected(Status.Code.PERMISSION_DENIED, () -> f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    membershipRequest(), "bad-scope", 1, "verified-fixture"));
            var base = service("10001", Set.of("identity:read"));
            var foreignResource = new ServiceIdentityPrincipal(base.subject(), base.tenantId(), base.clientId(), base.tokenId(),
                    URI.create("https://other.example/identity"), 1, base.scopes(), base.sourceBizCode(), base.sourceAppCode(),
                    base.sourceEnvironment(), base.credentialId(), base.issuedAt(), base.expiresAt(), base.appId(), base.scopeContext());
            f.verification.set(new AccessTokenVerification.Valid<>(foreignResource, foreignResource.scopes(), null, ISSUER));
            rejected(Status.Code.PERMISSION_DENIED, () -> f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    membershipRequest(), "bad-resource", 1, "verified-fixture"));
            f.verification.set(new AccessTokenVerification.Unavailable<>("IDENTITY_STATE_UNAVAILABLE"));
            rejected(Status.Code.UNAVAILABLE, () -> f.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    membershipRequest(), "authority-unavailable", 1, "verified-fixture"));
            f.verification.set(new AccessTokenVerification.Valid<>(base, base.scopes(), proof(), ISSUER));
            rejected(Status.Code.PERMISSION_DENIED, () -> f.invoke(IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod(),
                    BatchGetIdentityProfilesRequest.newBuilder().addSubjects("subject-a").build(), "unapproved", 1, "verified-fixture"));
            var unknown = IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod().toBuilder()
                    .setFullMethodName(IdentityDirectoryServiceGrpc.SERVICE_NAME + "/DeleteIdentity").build();
            rejected(Status.Code.UNIMPLEMENTED, () -> f.invoke(unknown,
                    BatchGetIdentityProfilesRequest.newBuilder().addSubjects("subject-a").build(), "unknown", 1, "verified-fixture"));
            org.mockito.Mockito.verifyNoInteractions(f.directory, f.memberships);
            assertThat(quota.commands).isEmpty();
            assertThat(f.physicalCalls).hasValue(0);
        }
    }

    @Test
    void twoRealH2cReplicasShareOneLogicalDebitAndCountEachPhysicalArrivalOnce() throws Exception {
        var shared = new CountingQuota();
        try (var first = new NativeFixture(shared, 1, true); var second = new NativeFixture(shared, 1, true)) {
            first.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(), "one-logical", 1, "verified-fixture");
            second.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(), "one-logical", 2, "verified-fixture");
            rejected(Status.Code.RESOURCE_EXHAUSTED, () -> second.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                    membershipRequest(), "another-logical", 1, "verified-fixture"));
            assertThat(shared.debits).hasValue(1);
            assertThat(shared.commands).hasSize(3).allSatisfy(command -> {
                assertThat(command.tenantId()).isEqualTo(10001);
                assertThat(command.clientId()).isEqualTo("rbac");
                assertThat(command.resource()).isEqualTo(RESOURCE.toASCIIString());
                assertThat(command.fullMethodName()).isEqualTo(MEMBERSHIP);
                assertThat(command.requestDigest()).isEqualTo(RpcInvocationMetadata.canonicalRequestDigest(membershipRequest()));
            });
            assertThat(first.physicalCalls.get() + second.physicalCalls.get()).isEqualTo(3);
            org.mockito.Mockito.verify(first.memberships).resolve("user-1", "10001");
            org.mockito.Mockito.verify(second.memberships).resolve("user-1", "10001");
        }
    }

    @Test
    void batchHasOneAttemptAndNoObservedAutomaticWireRetryOnUnavailable() throws Exception {
        try (var f = new NativeFixture(new CountingQuota(), 10, true)) {
            org.mockito.Mockito.when(f.directory.list()).thenThrow(new org.springframework.security.authentication.AuthenticationServiceException("sensitive backend state"));
            var request = BatchGetIdentityProfilesRequest.newBuilder().addSubjects("subject-a").build();
            rejected(Status.Code.UNAVAILABLE, () -> f.invoke(IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod(),
                    request, "batch-unavailable", 1, "verified-fixture"));
            assertThat(f.wireCalls).hasValue(1);
            org.mockito.Mockito.verify(f.directory).list();
            rejected(Status.Code.FAILED_PRECONDITION, () -> f.invoke(IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod(),
                    request, "batch-unavailable", 2, "verified-fixture"));
            org.mockito.Mockito.verify(f.directory).list();
        }
    }

    @Test
    @EnabledIfSystemProperty(named = "stellar.shoubing.test.redis-address", matches = "redis://127\\.0\\.0\\.1:[0-9]+")
    void productionRedisLuaCoalescesTwoNettyReplicasAndConcurrentClientsCannotOverspend() throws Exception {
        String address = System.getProperty("stellar.shoubing.test.redis-address");
        var keys = new top.egon.cola.component.accessguard.store.redisson.AccessGuardRedisKeyFactory(
                "identity-directory-it-" + java.util.UUID.randomUUID(), "shoubing-test");
        var firstRedis = org.redisson.Redisson.create(redisConfiguration(address));
        org.redisson.api.RedissonClient secondRedis = null;
        try {
            secondRedis = org.redisson.Redisson.create(redisConfiguration(address));
            var backendOne = new top.egon.cola.component.accessguard.store.redisson.RedissonLogicalQuotaBackend(firstRedis, keys);
            var backendTwo = new top.egon.cola.component.accessguard.store.redisson.RedissonLogicalQuotaBackend(secondRedis, keys);
            try (var first = new NativeFixture(backendOne, 1, true); var second = new NativeFixture(backendTwo, 1, true)) {
                first.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(), "one-real-logical", 1, "verified-fixture");
                second.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(), "one-real-logical", 2, "verified-fixture");
                rejected(Status.Code.RESOURCE_EXHAUSTED, () -> second.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(),
                        membershipRequest(), "next-real-logical", 1, "verified-fixture"));
                var original = quotaProbe("rbac", "one-real-logical");
                assertThat(firstRedis.<String>getBucket(keys.logicalQuotaState(original), org.redisson.client.codec.StringCodec.INSTANCE).get())
                        .isEqualTo("v1|1|0");
                assertThat(firstRedis.<String>getBucket(keys.logicalQuotaDecision(original), org.redisson.client.codec.StringCodec.INSTANCE).get())
                        .endsWith("|1|2");
                org.mockito.Mockito.verify(first.memberships).resolve("user-1", "10001");
                org.mockito.Mockito.verify(second.memberships).resolve("user-1", "10001");

                var old = service("10001", Set.of("identity:read"));
                var independentClient = new ServiceIdentityPrincipal("rbac-race", old.tenantId(), "rbac-race", old.tokenId(), old.resourceUri(),
                        old.resourceVersion(), old.scopes(), old.sourceBizCode(), old.sourceAppCode(), old.sourceEnvironment(), old.credentialId(),
                        old.issuedAt(), old.expiresAt(), old.appId(), old.scopeContext());
                var verified = new AccessTokenVerification.Valid<>(independentClient, independentClient.scopes(), proof(), ISSUER);
                first.verification.set(verified);
                second.verification.set(verified);
                var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
                try {
                    var start = new java.util.concurrent.CountDownLatch(1);
                    java.util.concurrent.Callable<Status.Code> one = () -> {
                        start.await();
                        try { first.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(), "race-one", 1, "verified-fixture"); return Status.Code.OK; }
                        catch (StatusRuntimeException failure) { return failure.getStatus().getCode(); }
                    };
                    java.util.concurrent.Callable<Status.Code> two = () -> {
                        start.await();
                        try { second.invoke(IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod(), membershipRequest(), "race-two", 1, "verified-fixture"); return Status.Code.OK; }
                        catch (StatusRuntimeException failure) { return failure.getStatus().getCode(); }
                    };
                    var firstCall = executor.submit(one);
                    var secondCall = executor.submit(two);
                    start.countDown();
                    assertThat(List.of(firstCall.get(3, TimeUnit.SECONDS), secondCall.get(3, TimeUnit.SECONDS)))
                            .containsExactlyInAnyOrder(Status.Code.OK, Status.Code.RESOURCE_EXHAUSTED);
                } finally { executor.shutdownNow(); }
                assertThat(firstRedis.<String>getBucket(keys.logicalQuotaState(quotaProbe("rbac-race", "race-one")),
                        org.redisson.client.codec.StringCodec.INSTANCE).get()).isEqualTo("v1|1|0");
                assertThat(first.physicalCalls.get() + second.physicalCalls.get()).isEqualTo(5);
            }
        } finally {
            if (secondRedis != null) secondRedis.shutdown();
            firstRedis.shutdown();
        }
    }

    private LogicalQuotaAcquireCommand quotaProbe(String client, String logicalId) {
        return new LogicalQuotaAcquireCommand(10001, client, RESOURCE.toASCIIString(), "identity-directory-v1", MEMBERSHIP,
                logicalId, RpcInvocationMetadata.canonicalRequestDigest(membershipRequest()), 1, 2, 1, 1, Duration.ofSeconds(5));
    }

    private static org.redisson.config.Config redisConfiguration(String address) {
        var config = new org.redisson.config.Config().setThreads(2).setNettyThreads(2);
        config.useSingleServer().setAddress(address).setConnectionMinimumIdleSize(1).setConnectionPoolSize(2)
                .setConnectTimeout(1000).setTimeout(2000).setRetryAttempts(0);
        return config;
    }

    private GetTenantMembershipRequest membershipRequest() {
        return GetTenantMembershipRequest.newBuilder().setTenantId("10001").setIdentitySub("user-1").build();
    }

    private top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO proof() {
        return new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO(
                ISSUER, RESOURCE, "a".repeat(64), "b".repeat(64), "c".repeat(64));
    }

    private IdpStarterProperties policies(boolean includeBatch) {
        var properties = new IdpStarterProperties();
        properties.getRpc().setEnabled(true);
        properties.getRpc().getProvider().setEnabled(true);
        var methods = new LinkedHashMap<String, IdpStarterProperties.RpcProviderMethodProperties>();
        for (var name : includeBatch ? List.of(BATCH, MEMBERSHIP) : List.of(MEMBERSHIP)) {
            methods.put(name, new IdpStarterProperties.RpcProviderMethodProperties().setRequired(true)
                    .setPrincipalKind(IdpStarterProperties.RpcPrincipalKindEnum.SERVICE)
                    .setScopeContext(top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext.TENANT)
                    .setRequiredScopes(Set.of("identity:read")).setExpectedResourceUri(RESOURCE));
        }
        properties.getRpc().getProvider().setMethods(methods);
        return properties;
    }

    /** Uses the official adapter to create the package-private authorization frame even for direct domain projections. */
    private <T> T authorized(String fullMethod, Supplier<T> action) {
        var principal = (ServiceIdentityPrincipal) top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcSecurityContext.currentPrincipalOrNull();
        var combined = mock(IdpJwtVerifier.class);
        org.mockito.Mockito.doAnswer(invocation -> new AccessTokenVerification.Valid<>(principal, principal.scopes(), proof(), ISSUER))
                .when(combined).verifyAny("verified-fixture");
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var interceptor = IdpRpcBearerServerInterceptor.createConfigured(mock(top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier.class),
                    combined, policies(true), null, factory.getValidator());
            interceptor.validateConfiguration();
            var result = new AtomicReference<T>();
            var call = new AuthorizationCall(fullMethod);
            var headers = new Metadata();
            headers.put(RpcMetadataKeys.AUTHORIZATION, "Bearer verified-fixture");
            var listener = interceptor.interceptCall(call, headers, (accepted, ignored) -> {
                result.set(action.get());
                return new ServerCall.Listener<Message>() { };
            });
            if (call.status != null) throw call.status.asRuntimeException();
            listener.onComplete();
            return result.get();
        }
    }

    private static void rejected(Status.Code status, Runnable invocation) {
        assertThatThrownBy(invocation::run).isInstanceOfSatisfying(StatusRuntimeException.class,
                failure -> assertThat(failure.getStatus().getCode()).isEqualTo(status));
    }

    private static final class AuthorizationCall extends ServerCall<Message, Message> {
        private final MethodDescriptor<Message, Message> method;
        private Status status;
        @SuppressWarnings("unchecked")
        private AuthorizationCall(String name) {
            method = (MethodDescriptor<Message, Message>) (MethodDescriptor<?, ?>) (name.equals(BATCH)
                    ? IdentityDirectoryServiceGrpc.getBatchGetIdentityProfilesMethod() : IdentityDirectoryServiceGrpc.getGetTenantMembershipMethod());
        }
        @Override public void request(int count) { }
        @Override public void sendHeaders(Metadata headers) { }
        @Override public void sendMessage(Message message) { }
        @Override public void close(Status value, Metadata trailers) { status = value; }
        @Override public boolean isCancelled() { return false; }
        @Override public MethodDescriptor<Message, Message> getMethodDescriptor() { return method; }
    }

    private final class NativeFixture implements AutoCloseable {
        private final jakarta.validation.ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        private final IdentityUserDirectory directory = mock(IdentityUserDirectory.class);
        private final TenantMembershipService memberships = mock(TenantMembershipService.class);
        private final AtomicInteger physicalCalls = new AtomicInteger();
        private final AtomicInteger wireCalls = new AtomicInteger();
        private final AtomicReference<AccessTokenVerification<?>> verification = new AtomicReference<>();
        private final Server server;
        private final ManagedChannel channel;
        private NativeFixture(LogicalQuotaBackend quota, long capacity, boolean includeBatchPolicy) throws Exception {
            org.mockito.Mockito.when(directory.list()).thenReturn(List.of(user("subject-a", "alice", "Alice", 4)));
            org.mockito.Mockito.when(memberships.resolve("user-1", "10001")).thenReturn(new TenantMembershipService.TenantMembershipProfile(
                    "user-1", "10001", "Acme", "Mario", IdentityTenantBO.Status.ACTIVE, IdentityUserStatus.ACTIVE,
                    IdentityTenantMembershipBO.Status.ACTIVE, TenantMembershipPort.MembershipStatus.ACTIVE, 4,
                    java.time.Instant.parse("2026-08-22T02:00:00Z")));
            var principal = service("10001", Set.of("identity:read"));
            verification.set(new AccessTokenVerification.Valid<>(principal, principal.scopes(), proof(), ISSUER));
            var jwt = mock(IdpJwtVerifier.class);
            org.mockito.Mockito.doAnswer(invocation -> verification.get()).when(jwt).verifyAny(org.mockito.ArgumentMatchers.anyString());
            List<io.grpc.ServerServiceDefinition> definitions;
            IdpRpcBearerServerInterceptor security;
            {
                var factory = validatorFactory;
                security = IdpRpcBearerServerInterceptor.createConfigured(mock(top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier.class),
                        jwt, policies(includeBatchPolicy), null, factory.getValidator());
                security.validateConfiguration();
                var provider = new IdentityDirectoryRpcProvider(directory, memberships);
                var contract = new RpcContractValidator(new ValidationUtils(factory.getValidator())).validate(IdentityDirectoryRpc.class);
                var binding = new RpcProviderBinding(provider, contract);
                var registry = new RpcProviderMethodRegistry(List.of(binding));
                var availability = new RpcProviderAvailabilityRegistry();
                availability.available(binding.serviceIdentity());
                var methods = new LinkedHashMap<String, EgonRpcProperties.RpcProviderMethodAdmissionConfig>();
                for (var method : List.of(BATCH, MEMBERSHIP)) {
                    methods.put(method, new EgonRpcProperties.RpcProviderMethodAdmissionConfig().setQuota("identity-directory-v1")
                            .setQuotaCapacity(capacity).setQuotaCost(1).setMaxAttempts(method.equals(MEMBERSHIP) ? 2 : 1)
                            .setReplayWindow(Duration.ofSeconds(5)).setPhysicalCapacity(100).setPhysicalWindow(Duration.ofSeconds(1)));
                }
                var configuration = new EgonRpcProperties.RpcProviderAdmissionConfig().setEnabled(true).setMaxConcurrent(4).setMethods(methods);
                var admission = new RpcProviderAdmissionComponent(new IdpRpcAdmissionIdentityResolver(), request -> {
                    physicalCalls.incrementAndGet();
                    return new RateLimitDecision(true, 99, Duration.ZERO);
                }, quota, configuration);
                definitions = new RpcServerServiceDefinitionFactory(availability,
                        List.of(new IdpPlatformConfiguration().identityDirectoryRpcExceptionMapper()), admission).create(registry);
            }
            ServerInterceptor count = new ServerInterceptor() {
                @Override public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call,
                        Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                    wireCalls.incrementAndGet();
                    return next.startCall(call, headers);
                }
            };
            server = new RpcProviderServerFactory().create("127.0.0.1", 0, definitions,
                    List.of(new RpcProviderServerInterceptor(), security, count)).start();
            channel = ManagedChannelBuilder.forAddress("127.0.0.1", server.getPort()).usePlaintext().disableRetry().build();
        }

        private <Req extends Message, Resp extends Message> Resp invoke(MethodDescriptor<Req, Resp> method, Req request,
                String logicalId, int attempt, String token) {
            var process = new RpcProcessIdentity("untrusted-header-app", "test", "default", "127.0.0.1", 1L, "fixture");
            var metadata = RpcConsumerClientInterceptor.forTarget(method.getServiceName(), IdentityDirectoryRpc.GROUP,
                    IdentityDirectoryRpc.VERSION, process, logicalId, attempt, RpcInvocationMetadata.canonicalRequestDigest(request));
            var authorization = new Metadata();
            if (token != null) authorization.put(RpcMetadataKeys.AUTHORIZATION, "Bearer " + token);
            var target = ClientInterceptors.intercept(channel, metadata, MetadataUtils.newAttachHeadersInterceptor(authorization));
            return ClientCalls.blockingUnaryCall(target, method, CallOptions.DEFAULT.withDeadlineAfter(2, TimeUnit.SECONDS), request);
        }
        @Override public void close() throws InterruptedException {
            try {
                channel.shutdownNow().awaitTermination(3, TimeUnit.SECONDS);
                server.shutdownNow().awaitTermination(3, TimeUnit.SECONDS);
            } finally { validatorFactory.close(); }
        }
    }

    /** Shared test double proves composition across replicas; root independently verifies production Redis/Lua atomicity. */
    private static final class CountingQuota implements LogicalQuotaBackend {
        private final List<LogicalQuotaAcquireCommand> commands = new ArrayList<>();
        private final AtomicInteger debits = new AtomicInteger();
        private final Map<ScopeVO, Long> remaining = new LinkedHashMap<>();
        private final Map<LogicalVO, LogicalQuotaAcquireCommand> accepted = new LinkedHashMap<>();
        @Override public synchronized LogicalQuotaDecisionVO acquire(LogicalQuotaAcquireCommand command) {
            commands.add(command);
            var scope = new ScopeVO(command.tenantId(), command.clientId(), command.resource(), command.quota(), command.fullMethodName());
            var logical = new LogicalVO(scope, command.logicalCallId());
            long balance = remaining.getOrDefault(scope, command.capacity());
            var previous = accepted.get(logical);
            if (command.attempt() > command.maxAttempts() || previous != null && command.attempt() <= previous.attempt()) {
                return new LogicalQuotaDecisionVO(false, LogicalQuotaDecisionVO.Reason.ATTEMPT_REJECTED, balance, 0);
            }
            if (previous != null) {
                if (!previous.requestDigest().equals(command.requestDigest())) return new LogicalQuotaDecisionVO(false, LogicalQuotaDecisionVO.Reason.CONFLICT, balance, 0);
                accepted.put(logical, command);
                return new LogicalQuotaDecisionVO(true, LogicalQuotaDecisionVO.Reason.REPLAY_ALLOWED, balance, command.attempt());
            }
            if (balance < command.cost()) return new LogicalQuotaDecisionVO(false, LogicalQuotaDecisionVO.Reason.EXHAUSTED, balance, 0);
            remaining.put(scope, balance - command.cost());
            accepted.put(logical, command);
            debits.incrementAndGet();
            return new LogicalQuotaDecisionVO(true, LogicalQuotaDecisionVO.Reason.ALLOWED, balance - command.cost(), command.attempt());
        }
        private record ScopeVO(long tenant, String client, String resource, String quota, String method) { }
        private record LogicalVO(ScopeVO scope, String id) { }
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
