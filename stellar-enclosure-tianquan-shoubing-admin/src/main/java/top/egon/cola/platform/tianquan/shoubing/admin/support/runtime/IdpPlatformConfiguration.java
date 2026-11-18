package top.egon.cola.platform.tianquan.shoubing.admin.support.runtime;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.dao.DataAccessException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import io.grpc.Status;
import top.egon.cola.component.rpc.provider.server.RpcProviderExceptionMapper;

import top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap.IdpBootstrapRunner;
import top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap.IdpDevelopmentTenantBootstrap;
import top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap.IdpBootstrapService;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.service.IdentityUserStateService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.component.outbox.store.OutboxStore;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@Profile("!oauth-migration")
public class IdpPlatformConfiguration {

    @Bean
    ApplicationRunner idpBootstrapApplicationRunner(
            IdpBootstrapService bootstrap,
            IdentityUserStateService stateService,
            OAuthSecurityProjectionComponent securityProjection,
            ObjectProvider<IdpDevelopmentTenantBootstrap> developmentTenants
    ) {
        IdpBootstrapRunner runner = new IdpBootstrapRunner(bootstrap);
        return (ApplicationArguments arguments) -> {
            securityProjection.recoverRegisteredRealms();
            runner.run(
                    arguments.getSourceArgs(),
                    Map.copyOf(System.getenv())
            );
            developmentTenants.ifAvailable(IdpDevelopmentTenantBootstrap::initializeAdministratorMemberships);
            stateService.reconcile();
        };
    }

    @Bean
    IdpRuntimeReadiness idpRuntimeReadiness(
            @Qualifier("outboxStore") OutboxStore outbox,
            @Qualifier("oauthManagementRealmResolver") OAuthManagementRealmResolver realms,
            @Qualifier("oAuthRealmRepository") OAuthRealmRepository realmRepository,
            @Qualifier("tenantJwkSourceComponent") JWKSource<SecurityContext> jwkSource,
            @Qualifier("authorizationServerSettings") AuthorizationServerSettings settings,
            @Qualifier("tianquanSecurityAuditReady") ObjectProvider<java.util.function.BooleanSupplier> auditReady
    ) {
        return () -> {
            boolean oauthReady = false;
            AuthorizationServerContext previous = AuthorizationServerContextHolder.getContext();
            try {
                var realm = realms.platformRealm();
                var active = realmRepository.findByIssuer(realm)
                        .filter(row -> "ACTIVE".equals(row.getStatus()) && row.getActiveKid() != null);
                if (active.isPresent()) {
                    AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
                        @Override
                        public String getIssuer() {
                            return realm.getIssuer().toASCIIString();
                        }
                        @Override
                        public AuthorizationServerSettings getAuthorizationServerSettings() {
                            return settings;
                        }
                    });
                    oauthReady = !jwkSource.get(new JWKSelector(new JWKMatcher.Builder()
                            .keyType(KeyType.RSA).privateOnly(true)
                            .keyID(active.get().getActiveKid()).build()), null).isEmpty();
                }
            } catch (OAuth2AuthenticationException | KeySourceException | DataAccessException notReady) {
                oauthReady = false;
            } finally {
                AuthorizationServerContextHolder.setContext(previous);
            }
            boolean outboxReady;
            try {
                outboxReady = outbox.countBacklog() >= 0L
                        && auditReady.getIfAvailable(() -> () -> false).getAsBoolean();
            } catch (DataAccessException unavailable) {
                outboxReady = false;
            }
            return new IdpRuntimeReadiness.Status(oauthReady, outboxReady);
        };
    }

    @Bean("idpRuntime")
    HealthIndicator idpRuntimeHealthIndicator(@Qualifier("idpRuntimeReadiness") IdpRuntimeReadiness readiness) {
        return () -> readiness.status().ready() ? Health.up().build() : Health.outOfService().build();
    }

    @Bean
    public RpcProviderExceptionMapper identityDirectoryRpcExceptionMapper() {
        return failure -> {
            if (failure instanceof AccessDeniedException) {
                return Optional.of(Status.PERMISSION_DENIED.asRuntimeException());
            }
            if (failure instanceof AuthenticationServiceException) {
                return Optional.of(Status.UNAVAILABLE.asRuntimeException());
            }
            if (failure instanceof NoSuchElementException) {
                return Optional.of(Status.NOT_FOUND.asRuntimeException());
            }
            if (failure instanceof IllegalArgumentException) {
                return Optional.of(Status.INVALID_ARGUMENT.asRuntimeException());
            }
            return Optional.empty();
        };
    }
}
