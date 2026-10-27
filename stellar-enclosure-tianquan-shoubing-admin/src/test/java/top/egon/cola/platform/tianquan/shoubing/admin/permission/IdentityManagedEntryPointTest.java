package top.egon.cola.platform.tianquan.shoubing.admin.permission;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.egon.cola.component.common.desensitize.strategy.SensitiveStrategyRegistry;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties;
import top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService;
import top.egon.cola.platform.tianquan.jianshen.starter.cache.SingleFlightSnapshotLoader;
import top.egon.cola.platform.tianquan.jianshen.starter.field.*;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.jianshen.starter.web.Rbac3AuthorizationExceptionHandler;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.controller.*;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.dto.*;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.vo.*;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.service.IdentityUserService;
import top.egon.cola.platform.tianquan.shoubing.admin.support.security.IdpAdminAuthorizationPort;
import top.egon.cola.platform.tianquan.shoubing.admin.support.security.IdpPermissionWebConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedUserTokenCarrier;
import java.lang.reflect.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static top.egon.cola.platform.tianquan.shoubing.admin.permission.IdpPermissionFixture.*;

/** Real compiled declarations, Spring method interception and actual host JSON converters; authority reads use explicit fixtures. */
@EnabledIfSystemProperty(named="permission.producer.enabled",matches="true")
class IdentityManagedEntryPointTest {
    @AfterEach void clear(){SecurityContextHolder.clearContext();org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();}

    @Test void everyManagedControllerMethodRejectsDirectAnonymousInvocationBeforeBusinessCode()throws Exception {
        var fixture=new Fixture();
        var scanner=new ClassPathScanningCandidateComponentProvider(false);scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));int count=0;
        for(var candidate:scanner.findCandidateComponents(PermissionProducerCoverageTest.ROOT)) {
            Class<?> type=Class.forName(candidate.getBeanClassName(),false,getClass().getClassLoader());
            if(PermissionProducerCoverageTest.NATIVE_CONTROLLERS.contains(type.getSimpleName()))continue;
            Object target=fixture.proxy(mock(type));
            for(Method method:type.getDeclaredMethods()) if(method.isAnnotationPresent(top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource.class)) {
                Object[] arguments=Arrays.stream(method.getParameterTypes()).map(t->t==int.class?0:t==long.class?0L:t==boolean.class?false:null).toArray();
                assertThatThrownBy(()->method.invoke(target,arguments)).as(method.toGenericString()).isInstanceOf(InvocationTargetException.class)
                        .hasCauseInstanceOf(org.springframework.security.authentication.AuthenticationCredentialsNotFoundException.class);count++;
            }
        }
        assertThat(count).isEqualTo(39);verifyNoInteractions(fixture.loader);
    }

    @Test void actualHttpInputRejectsMissingWriteUnknownAndExplicitNullBeforeBusinessState()throws Exception {
        var f=new Fixture();var mvc=f.mvc();
        f.user(Set.of(IdentityPermissionCodes.IDENTITY_USER_READ));
        mvc.perform(post("/api/v1/tianquan-shoubing/users").contentType(MediaType.APPLICATION_JSON).content("{\"username\":null,\"displayName\":\"x\"}"))
                .andExpect(status().isForbidden());verifyNoInteractions(f.service);
        f.user(Set.of(IdentityPermissionCodes.IDENTITY_USER_CREATE));
        mvc.perform(post("/api/v1/tianquan-shoubing/users").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"alice\",\"displayName\":\"x\",\"unknown\":true}"))
                .andExpect(status().isForbidden());verifyNoInteractions(f.service);
        when(f.service.create(any())).thenReturn(new CreatedIdentityUserVO("31","alice","Alice","ACTIVE","fixture-once"));
        mvc.perform(post("/api/v1/tianquan-shoubing/users").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"alice\",\"displayName\":\"Alice\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.subject").value("31")).andExpect(jsonPath("$.oneTimePassword").value("fixture-once"));
        verify(f.service).create(new CreateIdentityUserDTO("alice","Alice"));
        assertThat(f.originalMapper.getRegisteredModuleIds()).doesNotContain("Rbac3FieldJacksonModule");
    }

    @Test void writePermissionDoesNotRevealTheSharedReadProjection()throws Exception {
        var f=new Fixture();var mvc=f.mvc();
        var returned=new IdentityUserVO("31","alice","Alice","ACTIVE",0,null,null,2L);
        when(f.service.update(anyString(),any())).thenReturn(returned);
        f.user(Set.of(IdentityPermissionCodes.IDENTITY_USER_UPDATE));
        mvc.perform(patch("/api/v1/tianquan-shoubing/users/31").contentType(MediaType.APPLICATION_JSON).content("{\"displayName\":\"Alice\",\"status\":\"ACTIVE\",\"expectedVersion\":1}"))
                .andExpect(status().isOk()).andExpect(content().string("{}"));
        assertThat(f.originalMapper.valueToTree(returned).path("displayName").asText()).isEqualTo("Alice");
        f.user(Set.of(IdentityPermissionCodes.IDENTITY_USER_READ));when(f.service.list()).thenReturn(List.of(returned));
        mvc.perform(get("/api/v1/tianquan-shoubing/users")).andExpect(status().isOk()).andExpect(jsonPath("$[0].displayName").value("Alice"));
    }

    @Test void hostCurrentViewAndFieldCatalogShareTheSameScopeAndRejectTargetSelection()throws Exception {
        var f=new Fixture();var mvc=f.mvc();f.user(Set.of());
        mvc.perform(get("/api/v1/authorization/effective-permissions")).andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store"))
                .andExpect(jsonPath("$.data.catalogScope.applicationCode").value("tianquan-shoubing")).andExpect(jsonPath("$.data.catalogVersion").value("1"));
        mvc.perform(get("/api/v1/authorization/field-catalog").param("keys","tianquan-shoubing.field.CreateIdentityUserDTO.username","tianquan-shoubing.field.IdentityUserVO.username"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.catalogVersion").value("1"))
                .andExpect(jsonPath("$.data.fields['tianquan-shoubing.field.CreateIdentityUserDTO.username'].inputBinding").value(true))
                .andExpect(jsonPath("$.data.fields['tianquan-shoubing.field.IdentityUserVO.username'].inputBinding").value(false));
        mvc.perform(get("/api/v1/authorization/field-catalog").param("keys","tianquan-shoubing.field.CreateIdentityUserDTO.username").param("tenantId","21"))
                .andExpect(status().isBadRequest());
    }

    static class Fixture {
        final PermissionManifest manifest=IdpPermissionFixture.manifest();
        final CurrentRbac3User users=new CurrentRbac3User();
        final PermissionPolicyRegistry registry=new PermissionPolicyRegistry(manifest,ARTIFACT,CLOCK,List.of(SCOPE));
        final SingleFlightSnapshotLoader loader=mock(SingleFlightSnapshotLoader.class);
        final IdentityUserService service=mock(IdentityUserService.class);
        final ObjectMapper originalMapper=new ObjectMapper().findAndRegisterModules();
        final Rbac3StarterProperties.UserScopePolicyProperties scopes=new Rbac3StarterProperties.UserScopePolicyProperties().setEnabled(true)
                .setPermissionScopes(manifest.permissionDefinitions().stream().collect(java.util.stream.Collectors.toMap(PermissionManifest.PermissionDefinition::code,p->Set.of(p.code()))));
        final PermissionExecutionGuard execution=new PermissionExecutionGuard(registry,users,loader,null,scopes);
        final PermissionFieldBindingGuard input=new PermissionFieldBindingGuard(registry,users,()->null,scopes);
        Fixture()throws Exception { }
        void user(Set<String> codes){authenticate(manifest,codes,codes);when(loader.load(USER)).thenReturn(snapshot(manifest,codes));}
        Object proxy(Object target) {
            var manager=new Rbac3MethodAuthorizationManager(mock(AuthorizationService.class),execution);
            var pointcut=new StaticMethodMatcherPointcut(){@Override public boolean matches(Method method,Class<?> type){return manager.supports(method,type);}};
            var proxy=new ProxyFactory(target);proxy.setProxyTargetClass(true);proxy.addAdvisor(new AuthorizationManagerBeforeMethodInterceptor(pointcut,manager));return proxy.getProxy();
        }
        @SuppressWarnings("unchecked") MockMvc mvc() {
            ObjectProvider<RequestMappingHandlerAdapter> adapters=mock(ObjectProvider.class);
            ObjectProvider<RequestMappingHandlerMapping> routes=mock(ObjectProvider.class);
            var current=new CurrentEffectivePermissionView(users,registry,CLOCK);
            var fields=new PermissionFieldCatalog(registry,current,users);
            var converter=new MappingJackson2HttpMessageConverter(originalMapper);
            new IdpPermissionWebConfiguration(new PermissionJsonMapperFactory(users,SensitiveStrategyRegistry.defaults(),registry,input)).extendMessageConverters(List.of(converter));
            var mvc=MockMvcBuilders.standaloneSetup(proxy(new IdentityUserController(service,mock(IdpAdminAuthorizationPort.class))),
                    proxy(new IdentityCurrentPermissionController(current)),proxy(new IdentityFieldCatalogController(fields,adapters,routes)))
                    .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).setMessageConverters(converter)
                    .setControllerAdvice(new Rbac3AuthorizationExceptionHandler(),new InvalidInputAdvice())
                    .addFilter((req,res,chain)->{VerifiedUserTokenCarrier.set((jakarta.servlet.http.HttpServletRequest)req,"verified-fixture");chain.doFilter(req,res);}).build();
            when(adapters.getObject()).thenReturn(mvc.getDispatcherServlet().getWebApplicationContext().getBean(RequestMappingHandlerAdapter.class));
            when(routes.getObject()).thenReturn(mvc.getDispatcherServlet().getWebApplicationContext().getBean(RequestMappingHandlerMapping.class));
            return mvc;
        }
    }
    @org.springframework.web.bind.annotation.RestControllerAdvice static class InvalidInputAdvice {
        @org.springframework.web.bind.annotation.ExceptionHandler(IllegalArgumentException.class) org.springframework.http.ResponseEntity<Void> invalid(){return org.springframework.http.ResponseEntity.badRequest().build();}
    }
}
