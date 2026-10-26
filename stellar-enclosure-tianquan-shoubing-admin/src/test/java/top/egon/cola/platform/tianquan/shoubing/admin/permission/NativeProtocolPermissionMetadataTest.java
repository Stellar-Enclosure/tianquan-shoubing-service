package top.egon.cola.platform.tianquan.shoubing.admin.permission;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.config.AuthorizationServerConfiguration;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.config.OAuthNativeCorsProcessor;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.*;
import top.egon.cola.platform.tianquan.shoubing.rpc.contract.proto.v1.IdentityDirectoryServiceGrpc;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.starter.security.Rbac3MethodAuthorizationManager;
import java.lang.reflect.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class NativeProtocolPermissionMetadataTest {
    @Test void declarationsAreNotBeansHandlersOrASecondProtocolImplementation()throws Exception {
        assertThat(AnnotatedElementUtils.hasAnnotation(NativeProtocolPermissionMetadata.class,Component.class)).isFalse();
        assertThat(new ClassPathScanningCandidateComponentProvider(true).findCandidateComponents("top.egon.cola.platform.tianquan.shoubing.admin.permission"))
                .extracting(org.springframework.beans.factory.config.BeanDefinition::getBeanClassName).doesNotContain(NativeProtocolPermissionMetadata.class.getName());
        assertThat(Modifier.isFinal(NativeProtocolPermissionMetadata.class.getModifiers())).isTrue();
        for(var method:NativeProtocolPermissionMetadata.class.getDeclaredMethods()) {
            assertThat(Modifier.isStatic(method.getModifiers())).isTrue();assertThat(method.getParameterCount()).isZero();
            assertThatThrownBy(()->method.invoke(null)).isInstanceOf(InvocationTargetException.class).hasCauseInstanceOf(UnsupportedOperationException.class);
        }
        var advisor=new Rbac3MethodAuthorizationManager(mock(AuthorizationService.class));
        for(Class<?> controller:List.of(TenantLoginController.class,OAuthConsentController.class,OAuthLogoutController.class,OAuthPasswordChangeController.class,OAuthAuthorityController.class)) {
            for(var method:controller.getDeclaredMethods()) if(AnnotatedElementUtils.findMergedAnnotation(method,RequestMapping.class)!=null) {
                assertThat(method.getAnnotation(PermissionResource.class)).isNull();assertThat(advisor.supports(method,controller)).isFalse();
            }
        }
    }
    @Test void filterOwnedEndpointsMatchTheActualSasSettingsAndNativePreflightPaths()throws Exception {
        var factory=AuthorizationServerConfiguration.class.getDeclaredMethod("authorizationServerSettings");factory.setAccessible(true);
        var settings=(org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings)factory.invoke(new AuthorizationServerConfiguration());
        assertThat(paths("token")).containsExactlyInAnyOrder("/tenants/{tenantId}"+settings.getTokenEndpoint(),"/platform"+settings.getTokenEndpoint());
        assertThat(paths("revocation")).containsExactlyInAnyOrder("/tenants/{tenantId}"+settings.getTokenRevocationEndpoint(),"/platform"+settings.getTokenRevocationEndpoint());
        assertThat(paths("authorizationRequest")).containsExactly("/tenants/{tenantId}"+settings.getAuthorizationEndpoint());
        assertThat(paths("userInfo")).containsExactly("/tenants/{tenantId}"+settings.getOidcUserInfoEndpoint());
        assertThat(paths("jwks")).containsExactlyInAnyOrder("/tenants/{tenantId}"+settings.getJwkSetEndpoint(),"/platform"+settings.getJwkSetEndpoint());
        for(String method:List.of("tokenPreflight","userInfoPreflight","discoveryPreflight","jwksPreflight")) {
            assertThat(OAuthNativeCorsProcessor.isNativePreflight(new MockHttpServletRequest("OPTIONS",paths(method).getFirst().replace("{tenantId}","20")))).isTrue();
        }
        var rpc=IdentityDirectoryServiceGrpc.getServiceDescriptor().getMethods().stream().map(m->"/"+m.getFullMethodName()).collect(java.util.stream.Collectors.toSet());
        assertThat(rpc).containsExactlyInAnyOrder(paths("identityProfilesRpc").getFirst(),paths("tenantMembershipRpc").getFirst());
    }
    @Test void actualNativeControllerMappingsHaveMatchingMethodAndPathMetadata()throws Exception {
        Map<String,String> declarations=Map.of("TenantLoginController.loginPage","loginPage","OAuthConsentController.consentPage","consentPage",
                "OAuthLogoutController.form","logoutPage","OAuthLogoutController.logout","logout","OAuthPasswordChangeController.form","passwordChangePage",
                "OAuthPasswordChangeController.change","passwordChange","OAuthAuthorityController.resolve","securityState","OAuthAuthorityController.append","auditAppend");
        for(Class<?> controller:List.of(TenantLoginController.class,OAuthConsentController.class,OAuthLogoutController.class,OAuthPasswordChangeController.class,OAuthAuthorityController.class)) {
            for(var method:controller.getDeclaredMethods()) {
                var mapping=AnnotatedElementUtils.findMergedAnnotation(method,RequestMapping.class);if(mapping==null)continue;
                String declaration=declarations.get(controller.getSimpleName()+"."+method.getName());assertThat(declaration).isNotNull();
                String[] paths=mapping.path().length==0?mapping.value():mapping.path();
                assertThat(paths(declaration)).containsExactlyInAnyOrderElementsOf(Arrays.stream(paths).map(p->p.replace("{tenantId:[1-9][0-9]{0,18}}","{tenantId}")).toList());
                var methods=new HashSet<>(Arrays.asList(mapping.method()));if(methods.contains(org.springframework.web.bind.annotation.RequestMethod.GET))methods.add(org.springframework.web.bind.annotation.RequestMethod.HEAD);
                assertThat(Arrays.asList(NativeProtocolPermissionMetadata.class.getMethod(declaration).getAnnotation(RequestMapping.class).method())).containsExactlyInAnyOrderElementsOf(methods);
            }
        }
        assertThat(NativeProtocolPermissionMetadata.class.getMethod("oidcDiscovery").getAnnotation(PermissionResource.class).access()).isEqualTo(ResourceAccess.PUBLIC);
        assertThat(NativeProtocolPermissionMetadata.class.getMethod("token").getAnnotation(PermissionResource.class).access()).isEqualTo(ResourceAccess.INTERNAL);
    }
    private List<String> paths(String method)throws Exception{return Arrays.asList(NativeProtocolPermissionMetadata.class.getMethod(method).getAnnotation(RequestMapping.class).path());}
}
