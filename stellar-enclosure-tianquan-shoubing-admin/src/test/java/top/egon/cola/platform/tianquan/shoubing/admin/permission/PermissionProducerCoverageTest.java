package top.egon.cola.platform.tianquan.shoubing.admin.permission;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import java.lang.reflect.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

/** Matches javac output to actual controllers, native protocol declarations and reachable JSON DTO properties. */
@EnabledIfSystemProperty(named="permission.producer.enabled",matches="true")
class PermissionProducerCoverageTest {
    static final String ROOT="top.egon.cola.platform.tianquan.shoubing.admin.";
    static final Set<String> NATIVE_CONTROLLERS=Set.of("OAuthAuthorityController","OAuthConsentController","OAuthPasswordChangeController","TenantLoginController","OAuthLogoutController");
    private final ObjectMapper json=new ObjectMapper().findAndRegisterModules();
    @Test void currentMappingAndDtoInventoryExactlyMatchesTheCompilerFragment()throws Exception {
        var fragment=IdpPermissionFixture.fragment();
        assertThat(fragment.producer().id()).isEqualTo("tianquan-shoubing-java");
        assertThat(fragment.producer().expectedModules()).containsExactly("stellar-enclosure-tianquan-shoubing-admin");
        assertThat(fragment.producer().scannedModules()).containsExactly("stellar-enclosure-tianquan-shoubing-admin");
        Map<String,PermissionManifest.ResourceDefinition> resources=new TreeMap<>();fragment.resources().forEach(r->assertThat(resources.put(r.key(),r)).isNull());
        var scanner=new ClassPathScanningCandidateComponentProvider(false);scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));
        var mappings=new Mappings();Set<String> apis=new TreeSet<>(),fields=new TreeSet<>(),external=new TreeSet<>();int managed=0;
        for(var bean:scanner.findCandidateComponents(ROOT)) {
            Class<?> controller=Class.forName(bean.getBeanClassName(),false,getClass().getClassLoader());
            for(Method method:controller.getDeclaredMethods()) {
                var mapping=mappings.mapping(method,controller);if(mapping==null)continue;
                var declaration=method.getAnnotation(PermissionResource.class);
                if(NATIVE_CONTROLLERS.contains(controller.getSimpleName())) {assertThat(declaration).isNull();continue;}
                assertThat(declaration).as(method.toGenericString()).isNotNull();managed++;
                match(mapping,declaration,resources,apis,true);
                walk(method.getGenericReturnType(),true,resources,fields,external,new HashSet<>());
                for(Type parameter:method.getGenericParameterTypes())walk(parameter,false,resources,fields,external,new HashSet<>());
            }
        }
        for(Method method:NativeProtocolPermissionMetadata.class.getDeclaredMethods()) {
            match(mappings.mapping(method,NativeProtocolPermissionMetadata.class),method.getAnnotation(PermissionResource.class),resources,apis,false);
        }
        assertThat(managed).isEqualTo(37);assertThat(apis).hasSize(60);assertThat(fields).hasSize(193);
        assertThat(resources.values().stream().filter(r->r.type()==ResourceType.API).map(PermissionManifest.ResourceDefinition::key).toList()).containsExactlyInAnyOrderElementsOf(apis);
        assertThat(resources.values().stream().filter(r->r.type()==ResourceType.FIELD).map(PermissionManifest.ResourceDefinition::key).toList()).containsExactlyInAnyOrderElementsOf(fields);
        assertThat(external).containsExactlyInAnyOrder("top.egon.cola.component.common.core.pojo.ResultRecord",
                "top.egon.cola.platform.tianquan.jianshen.contract.auth.AuthorizationBootstrapView",
                "top.egon.cola.platform.tianquan.jianshen.contract.permission.EffectivePermissionSnapshot",
                "top.egon.cola.platform.tianquan.jianshen.contract.permission.FieldCatalogSnapshot",
                "top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal");
    }
    @Test void everyResourceAndPermissionHasAnOwnedSourceLabel()throws Exception {
        var manifest=IdpPermissionFixture.fragment();var messages=new TreeMap<String,PermissionManifest.Message>();
        manifest.messages().forEach(m->assertThat(messages.put(m.pageCode()+":"+m.key(),m)).isNull());
        manifest.resources().forEach(r->assertThat(messages).containsKey(r.i18n().pageCode()+":"+r.i18n().labelKey()));
        manifest.permissionDefinitions().forEach(p->assertThat(messages).containsKey(p.i18n().pageCode()+":"+p.i18n().labelKey()));
        assertThat(manifest.permissionDefinitions()).hasSize(21);assertThat(manifest.permissionReferences()).isEmpty();
        var status=manifest.resources().stream().filter(r->r.key().equals("tianquan-shoubing.field.UpdateIdentityUserDTO.status")).findFirst().orElseThrow();
        assertThat(status.fieldPolicy().valueType()).isEqualTo(PermissionManifest.JsonFieldType.STRING);
    }
    @SuppressWarnings("unchecked") private void match(RequestMappingInfo mapping,PermissionResource declaration,Map<String,PermissionManifest.ResourceDefinition> resources,Set<String> keys,boolean mvc) {
        assertThat(keys.add(declaration.key())).isTrue();var resource=resources.get(declaration.key());assertThat(resource).isNotNull();
        assertThat((List<String>)resource.target().get("paths")).containsExactlyInAnyOrderElementsOf(mapping.getPatternValues());
        var methods=new TreeSet<String>();mapping.getMethodsCondition().getMethods().forEach(m->methods.add(m.name()));if(mvc&&methods.contains("GET"))methods.add("HEAD");
        assertThat((List<String>)resource.target().get("methods")).containsExactlyInAnyOrderElementsOf(methods);
    }
    private void walk(Type generic,boolean output,Map<String,PermissionManifest.ResourceDefinition> resources,Set<String> fields,Set<String> external,Set<String> visiting)throws Exception {
        if(generic instanceof ParameterizedType p){for(Type t:p.getActualTypeArguments())walk(t,output,resources,fields,external,visiting);generic=p.getRawType();}
        if(!(generic instanceof Class<?> type)||type.isPrimitive()||type.isEnum())return;
        if(type.isArray()){walk(type.componentType(),output,resources,fields,external,visiting);return;}
        if(!type.getName().startsWith(ROOT)){if(type.getName().startsWith("top.egon."))external.add(type.getName());return;}
        if(!visiting.add(type.getName()+output))return;
        var description=output?json.getSerializationConfig().introspect(json.constructType(type)):json.getDeserializationConfig().introspect(json.constructType(type));
        for(var property:description.findProperties()) {
            if(property.getPrimaryMember()==null)continue;var field=type.getDeclaredField(property.getInternalName());
            var declaration=field.getAnnotation(PermissionResource.class);assertThat(declaration).as(type.getName()+":"+property.getName()).isNotNull();
            var resource=resources.get(declaration.key());assertThat(resource.target()).containsEntry("dto",type.getCanonicalName()).containsEntry("property",property.getName());
            fields.add(declaration.key());walk(field.getGenericType(),output,resources,fields,external,visiting);
        }
    }
    static final class Mappings extends RequestMappingHandlerMapping {RequestMappingInfo mapping(Method method,Class<?> type){return getMappingForMethod(method,type);}}
}
