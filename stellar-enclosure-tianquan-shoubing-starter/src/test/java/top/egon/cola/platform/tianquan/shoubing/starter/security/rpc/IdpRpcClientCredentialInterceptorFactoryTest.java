package top.egon.cola.platform.tianquan.shoubing.starter.security.rpc;

import com.google.protobuf.Empty;
import io.grpc.CallOptions;
import io.grpc.ClientInterceptors;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.protobuf.ProtoUtils;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import java.net.InetSocketAddress;
import io.grpc.CallCredentials;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Context;
import io.grpc.Status;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import top.egon.cola.component.rpc.consumer.generic.RpcGenericInvocation;
import top.egon.cola.component.rpc.context.identity.RpcProcessIdentity;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInvocation;
import top.egon.cola.component.rpc.context.invocation.RpcMetadataKeys;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.RpcConsumerModeEnum;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client.IdpServiceAuthorizationException;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.ArgumentMatchers.any;

class IdpRpcClientCredentialInterceptorFactoryTest {

    private final IdpRpcClientCredentialInterceptorFactory factory =
            new IdpRpcClientCredentialInterceptorFactory();
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();

    @BeforeEach void prepare() { validator.afterPropertiesSet(); }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
        org.slf4j.MDC.clear();
        validator.close();
    }

    @Test
    void serviceCredentialsAcquireOnGrpcExecutorWithOneFixedRequest() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var thread = new AtomicReference<Thread>();
        when(client.authorize(any())).thenAnswer(call -> { thread.set(Thread.currentThread()); return accessToken(); });
        var interceptor = configured(client, ServiceTokenContext.PLATFORM).create(IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process()));
        var channel = new CapturingChannel();
        var call = interceptor.interceptCall(realMethod(), CallOptions.DEFAULT, channel);
        var headers = new Metadata();
        call.start(new ClientCall.Listener<>() { }, headers);
        assertThat(headers.getAll(RpcMetadataKeys.AUTHORIZATION)).isNull();
        assertThat(channel.options.getCredentials()).as("SERVICE uses CallCredentials rather than blocking interceptCall").isNotNull();
        var queued = new AtomicReference<Runnable>();
        var applier = new RecordingApplier();
        channel.options.getCredentials().applyRequestMetadata(requestInfo(), queued::set, applier);
        verifyNoInteractions(client);
        try (var executor = Executors.newSingleThreadExecutor()) { executor.submit(queued.get()).get(5, TimeUnit.SECONDS); }
        assertThat(thread.get()).isNotSameAs(Thread.currentThread());
        assertThat(applier.completions.get()).isOne();
        assertThat(applier.headers.getAll(RpcMetadataKeys.AUTHORIZATION)).containsExactly("Bearer service-token");
        verify(client).authorize(new IdpServiceTokenRequest("inventory-client", "orders-app", IdpRpcBindingPropertiesTest.RESOURCE,
                ServiceTokenContext.PLATFORM, null, Set.of("inventory:read")));
    }

    @Test
    void typedAndNativeGenericUseOnlyTheExactStableServiceTarget() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var factory = configured(client, ServiceTokenContext.PLATFORM);
        var process = new RpcProcessIdentity("orders", "test", "different-host", 99, "different-instance");
        var generic = new RpcGenericInvocation(IdpRpcBindingPropertiesTest.BINDING_ID, IdpRpcBindingPropertiesTest.SERVICE,
                "internal", "v1", IdpRpcBindingPropertiesTest.METHOD, new byte[]{1}, 1000);
        for (var invocation : List.of(IdpRpcBindingPropertiesTest.invocation(process),
                RpcClientInvocation.generic(generic, process, "generic-1", IdpRpcBindingPropertiesTest.target()))) {
            var channel = new CapturingChannel();
            factory.create(invocation).interceptCall(realMethod(), CallOptions.DEFAULT, channel);
            assertThat(channel.options.getCredentials()).isNotNull();
        }
        verifyNoInteractions(client);
    }

    @Test
    void mismatchedChannelAuthorityRejectsBeforeTransportOrTokenAcquisition() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var interceptor = configured(client, ServiceTokenContext.PLATFORM)
                .create(IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process()));
        var channel = new CapturingChannel();
        channel.authority = "other-rpc.apps-test.svc.cluster.local:18122";
        assertThatThrownBy(() -> interceptor.interceptCall(realMethod(), CallOptions.DEFAULT, channel))
                .isInstanceOf(IllegalStateException.class);
        assertThat(channel.newCalls).isZero();
        verifyNoInteractions(client);
    }

    @Test
    void mismatchedMethodAndPerCallAuthorityRejectBeforeTransport() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var interceptor = configured(client, ServiceTokenContext.PLATFORM)
                .create(IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process()));
        var channel = new CapturingChannel();
        var otherMethod = realMethod().toBuilder().setFullMethodName("example.Inventory/Write").build();
        assertThatThrownBy(() -> interceptor.interceptCall(otherMethod, CallOptions.DEFAULT, channel))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> interceptor.interceptCall(realMethod(), CallOptions.DEFAULT.withAuthority("other.example:18122"), channel))
                .isInstanceOf(IllegalStateException.class);
        assertThat(channel.newCalls).isZero();
        verifyNoInteractions(client);
    }

    @Test
    void finalRequestInfoAuthorityAndMethodRejectBeforeSchedulingOrAcquisition() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        for (boolean wrongAuthority : List.of(true, false)) {
            var channel = serviceChannel(client);
            var info = requestInfo();
            if (wrongAuthority) { when(info.getAuthority()).thenReturn("other.example:18122"); }
            else { org.mockito.Mockito.doReturn(realMethod().toBuilder().setFullMethodName("example.Inventory/Write").build())
                    .when(info).getMethodDescriptor(); }
            var scheduled = new AtomicInteger();
            var applier = new RecordingApplier();
            channel.options.getCredentials().applyRequestMetadata(info, task -> scheduled.incrementAndGet(), applier);
            assertThat(scheduled).hasValue(0);
            assertThat(applier.completions).hasValue(1);
            assertThat(applier.status.getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
            assertThat(applier.status.getCause()).isNull();
            channel.lastCall.cancel("finished", null);
        }
        verifyNoInteractions(client);
    }

    @Test
    void nativeTargetNeverUsesUnconfiguredCompatibilityRelay() throws Exception {
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        IdpRpcSecurityContext.with(principal(), "verified-user").run(() ->
                assertThatThrownBy(() -> factory.create(invocation)).isInstanceOf(IllegalStateException.class));
    }

    @Test
    void configuredUserRelayRequiresApprovedSelectorAndFinalTransportBinding() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var properties = IdpRpcBindingPropertiesTest.properties(ServiceTokenContext.PLATFORM);
        properties.getRpc().getConsumer().getBindings().get("inventory").setMode(RpcConsumerModeEnum.USER_RELAY);
        var user = IdpRpcClientCredentialInterceptorFactory.createConfigured(client, properties, validator);
        var approved = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        var unapproved = IdpRpcBindingPropertiesTest.invocation(new RpcProcessIdentity("unapproved", "test", "local", 1, "one"));
        var interceptor = new AtomicReference<ClientInterceptor>();
        IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> {
            assertThatThrownBy(() -> user.create(unapproved)).isInstanceOf(IllegalStateException.class);
            interceptor.set(user.create(approved));
        });
        var channel = new CapturingChannel();
        var call = interceptor.get().interceptCall(realMethod(), CallOptions.DEFAULT, channel);
        var headers = new Metadata();
        call.start(new ClientCall.Listener<>() { }, headers);
        assertThat(headers.get(RpcMetadataKeys.AUTHORIZATION)).isNull();
        var wrong = requestInfo();
        when(wrong.getAuthority()).thenReturn("other.example:18122");
        var applier = new RecordingApplier();
        channel.options.getCredentials().applyRequestMetadata(wrong, Runnable::run, applier);
        assertThat(applier.status.getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
        call.cancel("finished", null);
        verifyNoInteractions(client);
    }

    @Test
    void frameworkAttemptAndTraceHeadersSurviveWhileProxyControlsAndDuplicatesAreRejected() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var channel = serviceChannel(client);
        var headers = new Metadata();
        headers.put(RpcMetadataKeys.ATTEMPT, "1");
        headers.put(RpcMetadataKeys.LOGICAL_CALL_ID, "logical-call");
        headers.put(RpcMetadataKeys.REQUEST_DIGEST, "a".repeat(64));
        headers.put(RpcMetadataKeys.TRACEPARENT, "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01");
        channel.lastCall.start(new ClientCall.Listener<>() { }, headers);
        assertThat(channel.call.headers).isSameAs(headers);
        assertThat(headers.get(RpcMetadataKeys.ATTEMPT)).isEqualTo("1");
        assertThat(headers.get(RpcMetadataKeys.TRACEPARENT)).isNotBlank();
        channel.lastCall.cancel("finished", null);
        for (boolean proxyControl : List.of(true, false)) {
            var rejected = serviceChannel(client);
            var invalid = new Metadata();
            if (proxyControl) { invalid.put(Metadata.Key.of("x-envoy-max-retries", Metadata.ASCII_STRING_MARSHALLER), "3"); }
            else { invalid.put(RpcMetadataKeys.ATTEMPT, "1"); invalid.put(RpcMetadataKeys.ATTEMPT, "2"); }
            assertThatThrownBy(() -> rejected.lastCall.start(new ClientCall.Listener<>() { }, invalid))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThat(rejected.call.started).isFalse();
        }
        verifyNoInteractions(client);
    }

    @Test
    void permanentCredentialFailuresAreDistinctFromTemporaryAuthorityFailure() throws Exception {
        var expected = java.util.Map.of("invalid_client", Status.Code.UNAUTHENTICATED,
                "invalid_scope", Status.Code.PERMISSION_DENIED, "access_denied", Status.Code.PERMISSION_DENIED,
                "registration_invalid", Status.Code.FAILED_PRECONDITION, "transport_binding_invalid", Status.Code.FAILED_PRECONDITION,
                "token_endpoint_origin_mismatch", Status.Code.FAILED_PRECONDITION,
                "authorization_timeout", Status.Code.UNAVAILABLE, "registration_projection_unavailable", Status.Code.UNAVAILABLE,
                "temporarily_unavailable", Status.Code.UNAVAILABLE);
        for (var entry : expected.entrySet()) {
            var client = mock(IdpServiceOAuth2Client.class);
            when(client.authorize(any())).thenThrow(new IdpServiceAuthorizationException(entry.getKey(),
                    new IllegalStateException("secret-token-endpoint")));
            var channel = serviceChannel(client);
            var applier = new RecordingApplier();
            channel.options.getCredentials().applyRequestMetadata(requestInfo(), Runnable::run, applier);
            assertThat(applier.completions).hasValue(1);
            assertThat(applier.status.getCode()).as(entry.getKey()).isEqualTo(entry.getValue());
            assertThat(applier.status.getCause()).isNull();
            assertThat(applier.status.getDescription()).doesNotContain("secret-token-endpoint");
            channel.lastCall.cancel("finished", null);
        }
    }

    @Test
    void productionBoundCredentialsReachRealNettyH2cForServiceAndApprovedUserRelay() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        when(client.authorize(any())).thenReturn(accessToken());
        var received = new java.util.concurrent.CopyOnWriteArrayList<String>();
        var method = MethodDescriptor.<Empty, Empty>newBuilder().setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName(IdpRpcBindingPropertiesTest.METHOD)
                .setRequestMarshaller(ProtoUtils.marshaller(Empty.getDefaultInstance()))
                .setResponseMarshaller(ProtoUtils.marshaller(Empty.getDefaultInstance())).build();
        var service = ServerServiceDefinition.builder(IdpRpcBindingPropertiesTest.SERVICE)
                .addMethod(method, ServerCalls.asyncUnaryCall((Empty request, io.grpc.stub.StreamObserver<Empty> observer) -> {
                    observer.onNext(Empty.getDefaultInstance()); observer.onCompleted();
                })).build();
        var capture = new ServerInterceptor() {
            @Override public <RequestT, ResponseT> ServerCall.Listener<RequestT> interceptCall(
                    ServerCall<RequestT, ResponseT> call, Metadata headers, ServerCallHandler<RequestT, ResponseT> next) {
                assertThat(headers.getAll(RpcMetadataKeys.AUTHORIZATION)).hasSize(1);
                received.add(headers.get(RpcMetadataKeys.AUTHORIZATION));
                return next.startCall(call, headers);
            }
        };
        var server = NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", 0))
                .addService(ServerInterceptors.intercept(service, capture)).build().start();
        // Only this fixture redirects the socket to loopback; production still sees its exact registered Service authority.
        var channel = NettyChannelBuilder.forAddress("127.0.0.1", server.getPort()).usePlaintext()
                .overrideAuthority(IdpRpcBindingPropertiesTest.AUTHORITY).disableRetry().build();
        try {
            var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
            var serviceInterceptor = configured(client, ServiceTokenContext.PLATFORM).create(invocation);
            assertThat(ClientCalls.blockingUnaryCall(ClientInterceptors.intercept(channel, serviceInterceptor), method,
                    CallOptions.DEFAULT.withDeadlineAfter(5, TimeUnit.SECONDS), Empty.getDefaultInstance())).isEqualTo(Empty.getDefaultInstance());
            var properties = IdpRpcBindingPropertiesTest.properties(ServiceTokenContext.PLATFORM);
            properties.getRpc().getConsumer().getBindings().get("inventory").setMode(RpcConsumerModeEnum.USER_RELAY);
            var user = IdpRpcClientCredentialInterceptorFactory.createConfigured(client, properties, validator);
            var userInterceptor = new AtomicReference<ClientInterceptor>();
            IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> userInterceptor.set(user.create(invocation)));
            assertThat(ClientCalls.blockingUnaryCall(ClientInterceptors.intercept(channel, userInterceptor.get()), method,
                    CallOptions.DEFAULT.withDeadlineAfter(5, TimeUnit.SECONDS), Empty.getDefaultInstance())).isEqualTo(Empty.getDefaultInstance());
            assertThat(received).containsExactly("Bearer service-token", "Bearer verified-user");
            verify(client).authorize(any());
        } finally {
            channel.shutdownNow(); server.shutdownNow();
            assertThat(channel.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
            assertThat(server.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void optInTenantIsCapturedSynchronouslyForLocallyAuthenticatedCaller() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        when(client.authorize(any())).thenReturn(accessToken());
        var localAuthentication = UsernamePasswordAuthenticationToken.authenticated("local-projection", "", List.of());
        SecurityContextHolder.getContext().setAuthentication(localAuthentication);
        var currentTenant = new AtomicReference<>("tenant-1");
        var resolutions = new AtomicInteger();
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        var factory = optInFactory(client, (actual, authentication) -> {
            assertThat(actual).isSameAs(invocation);
            assertThat(authentication).isSameAs(localAuthentication);
            resolutions.incrementAndGet();
            return Optional.of(currentTenant.get());
        });
        var interceptor = factory.create(invocation);
        assertThat(resolutions.get()).isOne();
        SecurityContextHolder.clearContext();
        currentTenant.set("untrusted-worker-tenant");
        var channel = new CapturingChannel();
        interceptor.interceptCall(realMethod(), CallOptions.DEFAULT, channel);
        var queued = new AtomicReference<Runnable>();
        var applier = new RecordingApplier();
        channel.options.getCredentials().applyRequestMetadata(requestInfo(), queued::set, applier);
        verifyNoInteractions(client);
        try (var executor = Executors.newSingleThreadExecutor()) { executor.submit(queued.get()).get(5, TimeUnit.SECONDS); }
        verify(client).authorize(new IdpServiceTokenRequest("tenant-inventory-client", "orders-app", IdpRpcBindingPropertiesTest.RESOURCE,
                ServiceTokenContext.TENANT, "tenant-1", Set.of("inventory:read")));
        assertThat(resolutions.get()).isOne();
        assertThat(applier.completions.get()).isOne();
    }

    private IdpRpcClientCredentialInterceptorFactory optInFactory(IdpServiceOAuth2Client client,
            IdpRpcClientTenantResolver resolver) {
        return IdpRpcClientCredentialInterceptorFactory.createConfigured(client,
                IdpRpcBindingPropertiesTest.properties(ServiceTokenContext.TENANT), validator, resolver);
    }

    @Test
    void tenantResolverEmptyRetainsVerifiedPrincipalAndExplicitValueCanSelectAnotherApprovedTenant() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        when(client.authorize(any())).thenReturn(accessToken());
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        for (boolean override : List.of(false, true)) {
            var properties = IdpRpcBindingPropertiesTest.properties(ServiceTokenContext.TENANT);
            properties.getRpc().getConsumer().getBindings().get("inventory").setTenantRegistrationIds(
                    java.util.Map.of("tenant-1", "tenant-inventory-client", "tenant-2", "target-inventory-client"));
            var selected = IdpRpcClientCredentialInterceptorFactory.createConfigured(client, properties, validator,
                    (ignored, authentication) -> override ? Optional.of("tenant-2") : Optional.empty());
            var interceptor = new AtomicReference<ClientInterceptor>();
            IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> interceptor.set(selected.create(invocation)));
            var channel = new CapturingChannel();
            interceptor.get().interceptCall(realMethod(), CallOptions.DEFAULT, channel);
            var applier = new RecordingApplier();
            channel.options.getCredentials().applyRequestMetadata(requestInfo(), Runnable::run, applier);
            assertThat(applier.completions.get()).isOne();
        }
        verify(client).authorize(new IdpServiceTokenRequest("tenant-inventory-client", "orders-app", IdpRpcBindingPropertiesTest.RESOURCE,
                ServiceTokenContext.TENANT, "tenant-1", Set.of("inventory:read")));
        verify(client).authorize(new IdpServiceTokenRequest("target-inventory-client", "orders-app", IdpRpcBindingPropertiesTest.RESOURCE,
                ServiceTokenContext.TENANT, "tenant-2", Set.of("inventory:read")));
    }

    @Test
    void nullDecisionAndResolverDenialNeverFallBackToValidPrincipal() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        List<IdpRpcClientTenantResolver> resolvers = List.of((ignored, authentication) -> null,
                (ignored, authentication) -> { throw new IllegalStateException("controlled denial"); });
        for (var resolver : resolvers) {
            IdpRpcSecurityContext.with(principal(), "verified-user").run(() ->
                    assertThatThrownBy(() -> optInFactory(client, resolver).create(invocation)).isInstanceOf(IllegalStateException.class));
        }
        verifyNoInteractions(client);
    }

    @Test
    void explicitEmptyBlankOrUnregisteredTenantNeverFallsBack() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        for (String invalid : List.of("", " ", "tenant-unregistered")) {
            IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> assertThatThrownBy(() ->
                    optInFactory(client, (ignored, authentication) -> Optional.of(invalid)).create(invocation))
                    .isInstanceOf(IllegalStateException.class));
        }
        verifyNoInteractions(client);
    }

    @Test
    void resolverIsNeverCalledBeforeNativeBindingApprovalOrForOtherCredentialModes() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var resolutions = new AtomicInteger();
        IdpRpcClientTenantResolver resolver = (ignored, authentication) -> { resolutions.incrementAndGet(); return Optional.of("tenant-1"); };
        var tenantFactory = optInFactory(client, resolver);
        var wrongProcess = IdpRpcBindingPropertiesTest.invocation(new RpcProcessIdentity("unapproved", "test", "local", 1, "test"));
        assertThatThrownBy(() -> tenantFactory.create(wrongProcess)).isInstanceOf(IllegalStateException.class);
        var otherTarget = new top.egon.cola.component.rpc.consumer.reference.RpcServiceTargetVO("other-rpc", 1, "apps-test", "other-rpc", 18122,
                Set.of(IdpRpcBindingPropertiesTest.METHOD));
        var generic = new RpcGenericInvocation("other-rpc", IdpRpcBindingPropertiesTest.SERVICE, "internal", "v1",
                IdpRpcBindingPropertiesTest.METHOD, new byte[]{1}, 1000);
        assertThatThrownBy(() -> tenantFactory.create(RpcClientInvocation.generic(generic, IdpRpcBindingPropertiesTest.process(), "call-1", otherTarget)))
                .isInstanceOf(IllegalStateException.class);
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        var platform = IdpRpcBindingPropertiesTest.properties(ServiceTokenContext.PLATFORM);
        assertThat(IdpRpcClientCredentialInterceptorFactory.createConfigured(client, platform, validator, resolver).create(invocation)).isNotNull();
        platform.getRpc().getConsumer().getBindings().get("inventory").setMode(RpcConsumerModeEnum.USER_RELAY);
        IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> assertThat(
                IdpRpcClientCredentialInterceptorFactory.createConfigured(client, platform, validator, resolver).create(invocation)).isNotNull());
        assertThat(resolutions.get()).isZero();
        verifyNoInteractions(client);
    }

    @Test
    void tenantRequestIsCapturedBeforeSchedulingAndNeverReadsWorkerMdc() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        when(client.authorize(any())).thenReturn(accessToken());
        var factory = configured(client, ServiceTokenContext.TENANT);
        var interceptor = new AtomicReference<ClientInterceptor>();
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> interceptor.set(factory.create(invocation)));
        org.slf4j.MDC.put("tenantId", "untrusted-tenant");
        var channel = new CapturingChannel();
        interceptor.get().interceptCall(realMethod(), CallOptions.DEFAULT, channel);
        assertThat(channel.options.getCredentials()).as("TENANT SERVICE must install CallCredentials").isNotNull();
        var queued = new AtomicReference<Runnable>();
        var applier = new RecordingApplier();
        channel.options.getCredentials().applyRequestMetadata(requestInfo(), queued::set, applier);
        try (var executor = Executors.newSingleThreadExecutor()) { executor.submit(queued.get()).get(5, TimeUnit.SECONDS); }
        verify(client).authorize(new IdpServiceTokenRequest("tenant-inventory-client", "orders-app", IdpRpcBindingPropertiesTest.RESOURCE,
                ServiceTokenContext.TENANT, "tenant-1", Set.of("inventory:read")));
        assertThat(applier.completions.get()).isOne();
        assertThat(org.slf4j.MDC.get("tenantId")).isEqualTo("untrusted-tenant");
    }

    @Test
    void userRelayNoServiceFallbackAndCredentialsCannotBeMerged() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var properties = IdpRpcBindingPropertiesTest.properties(ServiceTokenContext.PLATFORM);
        properties.getRpc().getConsumer().getBindings().get("inventory").setMode(RpcConsumerModeEnum.USER_RELAY);
        var user = IdpRpcClientCredentialInterceptorFactory.createConfigured(client, properties, validator);
        var invocation = IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process());
        assertThatThrownBy(() -> user.create(invocation)).isInstanceOf(IllegalStateException.class);
        var interceptor = new AtomicReference<ClientInterceptor>();
        IdpRpcSecurityContext.with(principal(), "verified-user").run(() -> interceptor.set(user.create(invocation)));
        var channel = new CapturingChannel();
        assertThatThrownBy(() -> interceptor.get().interceptCall(realMethod(), CallOptions.DEFAULT.withCallCredentials(mock(CallCredentials.class)), channel))
                .isInstanceOf(IllegalStateException.class);
        assertThat(channel.newCalls).isZero();
        var service = configured(client, ServiceTokenContext.PLATFORM).create(invocation);
        assertThatThrownBy(() -> service.interceptCall(realMethod(), CallOptions.DEFAULT.withCallCredentials(mock(CallCredentials.class)), channel))
                .isInstanceOf(IllegalStateException.class);
        var call = service.interceptCall(realMethod(), CallOptions.DEFAULT, channel);
        var headers = new Metadata();
        headers.put(RpcMetadataKeys.AUTHORIZATION, "Bearer other");
        assertThatThrownBy(() -> call.start(new ClientCall.Listener<>() { }, headers)).isInstanceOf(IllegalStateException.class);
        assertThat(channel.call.started).isFalse();
        verifyNoInteractions(client);
    }

    @Test
    void acquisitionAndSchedulingFailureCompleteOnceWithoutSensitiveCause() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        when(client.authorize(any())).thenThrow(new IllegalStateException("secret-endpoint-material"));
        for (Executor executor : List.<Executor>of(Runnable::run, task -> { throw new RejectedExecutionException("secret-endpoint-material"); })) {
            var channel = serviceChannel(client);
            var applier = new RecordingApplier();
            channel.options.getCredentials().applyRequestMetadata(requestInfo(), executor, applier);
            assertThat(applier.completions.get()).isOne();
            assertThat(applier.status.getCode()).isEqualTo(Status.Code.UNAVAILABLE);
            assertThat(applier.status.getCause()).isNull();
            assertThat(applier.status.getDescription()).isEqualTo("RPC credential acquisition unavailable");
            channel.lastCall.cancel("after failure", null);
            assertThat(applier.completions.get()).isOne();
        }
    }

    @Test
    void alreadyCancelledContextNeverRequestsCredentials() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        try (var cancelled = Context.current().withCancellation()) {
            cancelled.cancel(null);
            var channel = new AtomicReference<CapturingChannel>();
            cancelled.run(() -> {
                try { channel.set(serviceChannel(client)); } catch (Exception failure) { throw new AssertionError(failure); }
            });
            var applier = new RecordingApplier();
            channel.get().options.getCredentials().applyRequestMetadata(requestInfo(), Runnable::run, applier);
            assertThat(applier.completions.get()).isOne();
            assertThat(applier.status.getCode()).isEqualTo(Status.Code.CANCELLED);
        }
        verifyNoInteractions(client);
    }

    @Test
    void cancellationWhileAcquiringCompletesImmediatelyAndLateTokenCannotApply() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        when(client.authorize(any())).thenAnswer(call -> { entered.countDown(); assertThat(release.await(5, TimeUnit.SECONDS)).isTrue(); return accessToken(); });
        var channel = serviceChannel(client);
        var applier = new RecordingApplier();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var finished = new AtomicReference<java.util.concurrent.Future<?>>();
            channel.options.getCredentials().applyRequestMetadata(requestInfo(), task -> finished.set(executor.submit(task)), applier);
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            try {
                channel.lastCall.cancel("cancelled", null);
                assertThat(applier.completions.get()).isOne();
                assertThat(applier.status.getCode()).isEqualTo(Status.Code.CANCELLED);
            } finally { release.countDown(); }
            finished.get().get(5, TimeUnit.SECONDS);
        }
        assertThat(applier.completions.get()).isOne();
        assertThat(applier.headers).isNull();
    }

    @Test
    void callTerminationAndStartFailureCancelPendingAppliers() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        for (boolean startFailure : List.of(false, true)) {
            var channel = serviceChannel(client);
            var queued = new AtomicReference<Runnable>();
            var applier = new RecordingApplier();
            channel.options.getCredentials().applyRequestMetadata(requestInfo(), queued::set, applier);
            if (startFailure) {
                channel.call.failStart = true;
                assertThatThrownBy(() -> channel.lastCall.start(new ClientCall.Listener<>() { }, new Metadata())).isInstanceOf(IllegalStateException.class);
            } else {
                channel.lastCall.start(new ClientCall.Listener<>() { }, new Metadata());
                channel.call.listener.onClose(Status.OK, new Metadata());
            }
            queued.get().run();
            assertThat(applier.completions.get()).isOne();
            assertThat(applier.status.getCode()).isEqualTo(Status.Code.CANCELLED);
        }
        verifyNoInteractions(client);
    }

    @Test
    void createFailureCancelsEvenAnApplierInvokedAfterTheDelegateFails() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        var channel = new CapturingChannel();
        channel.failCreate = true;
        var interceptor = configured(client, ServiceTokenContext.PLATFORM).create(IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process()));
        assertThatThrownBy(() -> interceptor.interceptCall(realMethod(), CallOptions.DEFAULT, channel)).isInstanceOf(IllegalStateException.class);
        var applier = new RecordingApplier();
        channel.options.getCredentials().applyRequestMetadata(requestInfo(), Runnable::run, applier);
        assertThat(applier.completions.get()).isOne(); assertThat(applier.status.getCode()).isEqualTo(Status.Code.CANCELLED);
        verifyNoInteractions(client);
    }

    @Test
    void successAndCancellationRaceNeverCompletesAnApplierTwice() throws Exception {
        var client = mock(IdpServiceOAuth2Client.class);
        when(client.authorize(any())).thenReturn(accessToken());
        try (var workers = Executors.newFixedThreadPool(2)) {
            for (int iteration = 0; iteration < 20; iteration++) {
                var channel = serviceChannel(client);
                var applier = new RecordingApplier();
                var ready = new CountDownLatch(2); var release = new CountDownLatch(1);
                var applied = new AtomicReference<java.util.concurrent.Future<?>>();
                channel.options.getCredentials().applyRequestMetadata(requestInfo(), task -> applied.set(workers.submit(() -> {
                    ready.countDown(); await(release); task.run();
                })), applier);
                var cancelled = workers.submit(() -> { ready.countDown(); await(release); channel.lastCall.cancel("cancel", null); });
                try { assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue(); } finally { release.countDown(); }
                applied.get().get(5, TimeUnit.SECONDS); cancelled.get(5, TimeUnit.SECONDS);
                assertThat(applier.completions.get()).isOne();
                if (applier.headers != null) { assertThat(applier.headers.getAll(RpcMetadataKeys.AUTHORIZATION)).containsExactly("Bearer service-token"); }
                else { assertThat(applier.status.getCode()).isEqualTo(Status.Code.CANCELLED); }
            }
        }
    }

    private static void await(CountDownLatch latch) {
        try { if (!latch.await(5, TimeUnit.SECONDS)) { throw new AssertionError("bounded worker barrier timed out"); } }
        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
    }

    private IdpRpcClientCredentialInterceptorFactory configured(IdpServiceOAuth2Client client, ServiceTokenContext context) {
        return IdpRpcClientCredentialInterceptorFactory.createConfigured(client, IdpRpcBindingPropertiesTest.properties(context), validator);
    }

    private CapturingChannel serviceChannel(IdpServiceOAuth2Client client) throws Exception {
        var channel = new CapturingChannel();
        channel.lastCall = configured(client, ServiceTokenContext.PLATFORM).create(IdpRpcBindingPropertiesTest.invocation(IdpRpcBindingPropertiesTest.process()))
                .interceptCall(realMethod(), CallOptions.DEFAULT, channel);
        assertThat(channel.options.getCredentials()).as("SERVICE must install CallCredentials").isNotNull();
        return channel;
    }

    private MethodDescriptor<Object, Object> realMethod() {
        return MethodDescriptor.<Object, Object>newBuilder().setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName(IdpRpcBindingPropertiesTest.METHOD).setRequestMarshaller(mock(MethodDescriptor.Marshaller.class))
                .setResponseMarshaller(mock(MethodDescriptor.Marshaller.class)).build();
    }

    private CallCredentials.RequestInfo requestInfo() {
        var info = mock(CallCredentials.RequestInfo.class);
        when(info.getAuthority()).thenReturn(IdpRpcBindingPropertiesTest.AUTHORITY);
        org.mockito.Mockito.doReturn(realMethod()).when(info).getMethodDescriptor();
        return info;
    }

    private OAuth2AccessToken accessToken() {
        var issued = Instant.parse("2026-10-11T00:00:00Z");
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "service-token", issued, issued.plus(Duration.ofMinutes(5)), Set.of("inventory:read"));
    }

    private static final class RecordingApplier extends CallCredentials.MetadataApplier {
        private final AtomicInteger completions = new AtomicInteger();
        private volatile Metadata headers;
        private volatile Status status;
        @Override public void apply(Metadata metadata) { completions.incrementAndGet(); headers = metadata; }
        @Override public void fail(Status value) { completions.incrementAndGet(); status = value; }
    }

    @Test
    void forwardsOnlyTheVerifiedServletUserToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request)
        );
        VerifiedUserTokenCarrier.set(request, "servlet-token");

        Metadata headers = start(factory.create(invocation()));

        assertThat(headers.getAll(RpcMetadataKeys.AUTHORIZATION))
                .containsExactly("Bearer servlet-token");
    }

    @Test
    void forwardsTheVerifiedRpcUserTokenAcrossAnotherHop() {
        Metadata[] observed = new Metadata[1];

        IdpRpcSecurityContext.with(principal(), "rpc-token").run(() ->
                observed[0] = start(factory.create(invocation()))
        );

        assertThat(observed[0].getAll(RpcMetadataKeys.AUTHORIZATION))
                .containsExactly("Bearer rpc-token");
    }

    @Test
    void leavesAuthorizationAbsentForAnonymousCalls() {
        Metadata headers = start(factory.create(invocation()));

        assertThat(headers.getAll(RpcMetadataKeys.AUTHORIZATION)).isNull();
    }

    @Test
    void rejectsPreexistingAuthorizationInsteadOfMergingCredentials() {
        Metadata headers = new Metadata();
        headers.put(RpcMetadataKeys.AUTHORIZATION, "Bearer untrusted-token");
        CapturingChannel channel = new CapturingChannel();
        AtomicReference<ClientCall<Object, Object>> call =
                new AtomicReference<>();

        IdpRpcSecurityContext.with(principal(), "verified-token").run(() -> {
            call.set(factory.create(invocation())
                    .interceptCall(method(), CallOptions.DEFAULT, channel));
        });
        assertThatThrownBy(() -> call.get().start(
                        new ClientCall.Listener<>() {
                        },
                        headers
                )).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("authorization");

        assertThat(channel.call.started).isFalse();
        assertThat(headers.getAll(RpcMetadataKeys.AUTHORIZATION))
                .containsExactly("Bearer untrusted-token");
    }

    private Metadata start(ClientInterceptor interceptor) {
        CapturingChannel channel = new CapturingChannel();
        ClientCall<Object, Object> call = interceptor.interceptCall(
                method(),
                CallOptions.DEFAULT,
                channel
        );
        Metadata headers = new Metadata();
        call.start(new ClientCall.Listener<>() {
        }, headers);
        assertThat(channel.call.started).isTrue();
        return headers;
    }

    @SuppressWarnings("unchecked")
    private MethodDescriptor<Object, Object> method() {
        return mock(MethodDescriptor.class);
    }

    private RpcClientInvocation invocation() {
        return mock(RpcClientInvocation.class);
    }

    private IdentityPrincipal principal() {
        Instant issuedAt = Instant.parse("2026-08-15T00:00:00Z");
        return new IdentityPrincipal(
                "user-1",
                "tenant-1",
                "token-1",
                Set.of("resource-1"),
                issuedAt,
                issuedAt.plusSeconds(300),
                AuthenticationContext.of("PASSWORD", issuedAt)
        );
    }

    private static final class CapturingChannel extends Channel {

        private final CapturingClientCall call = new CapturingClientCall();
        private CallOptions options;
        private int newCalls;
        private ClientCall<Object, Object> lastCall;
        private boolean failCreate;
        private String authority = IdpRpcBindingPropertiesTest.AUTHORITY;

        @Override
        @SuppressWarnings("unchecked")
        public <RequestT, ResponseT> ClientCall<RequestT, ResponseT> newCall(
                MethodDescriptor<RequestT, ResponseT> methodDescriptor,
                CallOptions callOptions
        ) {
            options = callOptions;
            newCalls++;
            if (failCreate) { throw new IllegalStateException("controlled create failure"); }
            return (ClientCall<RequestT, ResponseT>) call;
        }

        @Override
        public String authority() {
            return authority;
        }
    }

    private static final class CapturingClientCall
            extends ClientCall<Object, Object> {

        private boolean started;
        private boolean failStart;
        private Listener<Object> listener;
        private Metadata headers;

        @Override
        public void start(Listener<Object> listener, Metadata headers) {
            if (failStart) { throw new IllegalStateException("controlled start failure"); }
            this.listener = listener;
            this.headers = headers;
            started = true;
        }

        @Override
        public void request(int numMessages) {
        }

        @Override
        public void cancel(String message, Throwable cause) {
        }

        @Override
        public void halfClose() {
        }

        @Override
        public void sendMessage(Object message) {
        }
    }
}
