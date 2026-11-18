package top.egon.cola.platform.tianquan.shoubing.starter.security.rpc;

import com.google.protobuf.Empty;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.component.rpc.provider.server.RpcAdmissionIdentityVO;
import top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.IdpPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;

import java.net.URI;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdpRpcAdmissionIdentityResolverTest {

    private static final String METHOD = "example.Inventory/Read";
    private static final URI ISSUER = URI.create("https://identity.example/tenants/1001");
    private static final URI RESOURCE = URI.create("https://inventory.example/resources/catalog");
    private static final Set<String> SCOPES = Set.of("inventory:read");
    private static final TokenAuditProofBO PROOF = new TokenAuditProofBO(
            ISSUER, RESOURCE, "1".repeat(64), "2".repeat(64), "3".repeat(64));

    private final IdpRpcAdmissionIdentityResolver resolver = new IdpRpcAdmissionIdentityResolver();

    @AfterEach
    void clearSpringContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void rejectsMissingGrpcAuthenticationEvenWithForgedSpringProof() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        var forged = UsernamePasswordAuthenticationToken.authenticated(service, "", authorities(SCOPES));
        forged.setDetails(PROOF);
        withSpring(forged, () -> {
            rejected(Status.Code.UNAUTHENTICATED, METHOD);
            return null;
        });
    }

    @Test
    void legacyPrincipalScopeCannotCreateMethodAuthorization() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        IdpRpcSecurityContext.with(service, "verified-service-token", PROOF, null, SCOPES).run(() ->
                withSpring(authentication(service, SCOPES, ISSUER, PROOF), () -> {
                    rejected(Status.Code.UNAUTHENTICATED, METHOD);
                    return null;
                }));
    }

    @Test
    void authorizedServiceCallbackBindsOnlyVerifiedTenantClientAndCanonicalResource() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        var identity = inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, ISSUER, PROOF),
                () -> resolver.resolve(METHOD, Empty.getDefaultInstance()));

        assertThat(identity).isEqualTo(new RpcAdmissionIdentityVO(1001L, "inventory-client", RESOURCE.toASCIIString()));
        var forgedBody = Struct.newBuilder()
                .putFields("tenantId", Value.newBuilder().setStringValue("9999").build())
                .putFields("clientId", Value.newBuilder().setStringValue("forged-client").build())
                .putFields("resource", Value.newBuilder().setStringValue("https://attacker.example").build())
                .build();
        assertThat(inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, ISSUER, PROOF), () -> resolver.resolve(METHOD, forgedBody)))
                .isEqualTo(identity);
        assertThat(IdpRpcSecurityContext.authorizedMethodOrNull()).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void auditDisabledPairStillRequiresVerifierOwnedMethodAndIssuer() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        assertThat(inContext(service, SCOPES, null, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, ISSUER, null),
                () -> resolver.resolve(METHOD, Empty.getDefaultInstance())).clientId()).isEqualTo(service.clientId());
    }

    @Test
    void ownedAuthorizedCallbackPublishesAndRestoresSpringIdentity() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        var previous = UsernamePasswordAuthenticationToken.authenticated("previous-user", "", java.util.List.of());
        var result = new AtomicReference<RpcAdmissionIdentityVO>();
        withSpring(previous, () -> {
            IdpRpcSecurityContext.with(service, "verified-service-token", PROOF, null, SCOPES, ISSUER,
                    frame(METHOD, ISSUER, RESOURCE)).run(() ->
                    IdpRpcSecurityContext.runWithSpringSecurity(service, SCOPES, PROOF, ISSUER,
                            () -> result.set(resolver.resolve(METHOD, Empty.getDefaultInstance()))));
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(previous);
            assertThat(IdpRpcSecurityContext.authorizedMethodOrNull()).isNull();
            return null;
        });
        assertThat(result.get()).isEqualTo(new RpcAdmissionIdentityVO(1001L, service.clientId(), RESOURCE.toASCIIString()));
    }

    @Test
    void differentMethodCannotBorrowAuthorizedFrame() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, ISSUER, PROOF), () -> {
                    rejected(Status.Code.PERMISSION_DENIED, "example.Inventory/Delete");
                    return null;
                });
    }

    @Test
    void rejectsMissingOrNonIdpSpringAuthentication() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        var unauthenticated = authentication(service, SCOPES, ISSUER, PROOF);
        unauthenticated.setAuthenticated(false);
        for (var authentication : new Authentication[]{null,
                unauthenticated,
                UsernamePasswordAuthenticationToken.authenticated(service, "", authorities(SCOPES))}) {
            inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE), authentication, () -> {
                rejected(Status.Code.UNAUTHENTICATED, METHOD);
                return null;
            });
        }
    }

    @Test
    void rejectsDifferentSpringPrincipalEvenWhenItsValuesAreEqual() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        var copied = new ServiceIdentityPrincipal(service.subject(), service.tenantId(), service.clientId(), service.tokenId(),
                service.resourceUri(), service.resourceVersion(), service.scopes(), service.sourceBizCode(),
                service.sourceAppCode(), service.sourceEnvironment(), service.credentialId(), service.issuedAt(),
                service.expiresAt(), service.appId(), service.scopeContext());
        assertThat(copied).isEqualTo(service).isNotSameAs(service);
        inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(copied, SCOPES, ISSUER, PROOF), () -> {
                    rejected(Status.Code.PERMISSION_DENIED, METHOD);
                    return null;
                });
    }

    @Test
    void rejectsSpringIssuerAndScopeAuthorityMismatch() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        for (var authentication : new IdpAuthenticationToken[]{
                authentication(service, SCOPES, URI.create("https://other.example/tenants/1001"), PROOF),
                authentication(service, Set.of("inventory:write"), ISSUER, PROOF),
                authentication(service, Set.of("inventory:read", "inventory:write"), ISSUER, PROOF)}) {
            inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE), authentication, () -> {
                rejected(Status.Code.PERMISSION_DENIED, METHOD);
                return null;
            });
        }
        inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, null, PROOF), () -> {
                    rejected(Status.Code.UNAUTHENTICATED, METHOD);
                    return null;
                });
    }

    @Test
    void rejectsProofMismatchAndResourceFrameMismatch() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        var wrongProof = new TokenAuditProofBO(ISSUER, RESOURCE, "4".repeat(64), "5".repeat(64), "6".repeat(64));
        for (var details : new Object[]{wrongProof, null, "forged-proof"}) {
            inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                    authentication(service, SCOPES, ISSUER, details), () -> {
                        rejected(Status.Code.PERMISSION_DENIED, METHOD);
                        return null;
                    });
        }
        inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, URI.create("https://other.example/resource")),
                authentication(service, SCOPES, ISSUER, PROOF), () -> {
                    rejected(Status.Code.PERMISSION_DENIED, METHOD);
                    return null;
                });
        var wrongIssuerProof = new TokenAuditProofBO(URI.create("https://other.example/tenant"), RESOURCE, null, null, null);
        inContext(service, SCOPES, wrongIssuerProof, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, ISSUER, wrongIssuerProof), () -> {
                    rejected(Status.Code.PERMISSION_DENIED, METHOD);
                    return null;
                });
    }

    @Test
    void rejectsGrpcScopeMismatchRatherThanBorrowingSpringAuthorities() {
        var service = service("1001", "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        inContext(service, Set.of("inventory:write"), PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, Set.of("inventory:write"), ISSUER, PROOF), () -> {
                    rejected(Status.Code.PERMISSION_DENIED, METHOD);
                    return null;
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-1", "+1", "01", "tenant-1", "9223372036854775808"})
    void refusesUnsupportedTenantWithoutHashingOrZeroFallback(String tenant) {
        var service = service(tenant, "inventory-client", RESOURCE, ServiceTokenContext.TENANT);
        inContext(service, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                authentication(service, SCOPES, ISSUER, PROOF), () -> {
                    rejected(Status.Code.PERMISSION_DENIED, METHOD);
                    return null;
                });
    }

    @Test
    void rejectsPlatformAndUserWithoutInventingServiceQuotaSubject() {
        var platform = service(null, "platform-client", RESOURCE, ServiceTokenContext.PLATFORM);
        var now = Instant.now();
        var user = new IdentityPrincipal("user-1", "1001", "user-token", Set.of(RESOURCE.toASCIIString()),
                now.minusSeconds(30), now.plusSeconds(300), AuthenticationContext.of("PASSWORD", now.minusSeconds(30)));
        for (var principal : new IdpPrincipal[]{platform, user}) {
            inContext(principal, SCOPES, PROOF, frame(METHOD, ISSUER, RESOURCE),
                    authentication(principal, SCOPES, ISSUER, PROOF), () -> {
                        rejected(Status.Code.PERMISSION_DENIED, METHOD);
                        return null;
                    });
        }
    }

    @Test
    void boundsClientAndCanonicalResourceBeforeReturningQuotaIdentity() {
        for (var service : new ServiceIdentityPrincipal[]{
                service("1001", "x".repeat(257), RESOURCE, ServiceTokenContext.TENANT),
                service("1001", "inventory-client", URI.create("https://inventory.example/" + "x".repeat(240)), ServiceTokenContext.TENANT)}) {
            var proof = new TokenAuditProofBO(ISSUER, service.resourceUri(), null, null, null);
            inContext(service, SCOPES, proof, frame(METHOD, ISSUER, service.resourceUri()),
                    authentication(service, SCOPES, ISSUER, proof), () -> {
                        rejected(Status.Code.PERMISSION_DENIED, METHOD);
                        return null;
                    });
        }
    }

    private void rejected(Status.Code code, String method) {
        assertThatThrownBy(() -> resolver.resolve(method, Empty.getDefaultInstance()))
                .isInstanceOfSatisfying(StatusRuntimeException.class, exception -> {
                    assertThat(exception.getStatus().getCode()).isEqualTo(code);
                    assertThat(exception.getMessage()).doesNotContain("inventory-client", "verified-service-token");
                });
    }

    private static ServiceIdentityPrincipal service(String tenant, String client, URI resource, ServiceTokenContext context) {
        var now = Instant.now();
        return new ServiceIdentityPrincipal(client, tenant, client, "service-token-id", resource, 3L, SCOPES,
                "commerce", "inventory", "prod", "credential-1", now.minusSeconds(30), now.plusSeconds(300),
                "inventory-app", context);
    }

    private static IdpRpcSecurityContext.AuthorizedMethodVO frame(String method, URI issuer, URI resource) {
        return new IdpRpcSecurityContext.AuthorizedMethodVO(method, issuer, resource);
    }

    private static IdpAuthenticationToken authentication(IdpPrincipal principal, Set<String> scopes, URI issuer, Object proof) {
        var authentication = new IdpAuthenticationToken(principal, authorities(scopes), issuer);
        authentication.setDetails(proof);
        return authentication;
    }

    private static java.util.List<SimpleGrantedAuthority> authorities(Set<String> scopes) {
        return scopes.stream().map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope)).toList();
    }

    private static <T> T inContext(IdpPrincipal principal, Set<String> scopes, TokenAuditProofBO proof,
            IdpRpcSecurityContext.AuthorizedMethodVO frame, Authentication authentication, Supplier<T> action) {
        Context context = IdpRpcSecurityContext.with(principal, "verified-service-token", proof, null, scopes, ISSUER, frame);
        Context previous = context.attach();
        try {
            return withSpring(authentication, action);
        } finally {
            context.detach(previous);
        }
    }

    private static <T> T withSpring(Authentication authentication, Supplier<T> action) {
        var previous = SecurityContextHolder.getContext();
        var current = SecurityContextHolder.createEmptyContext();
        current.setAuthentication(authentication);
        try {
            SecurityContextHolder.setContext(current);
            return action.get();
        } finally {
            SecurityContextHolder.setContext(previous);
        }
    }
}
