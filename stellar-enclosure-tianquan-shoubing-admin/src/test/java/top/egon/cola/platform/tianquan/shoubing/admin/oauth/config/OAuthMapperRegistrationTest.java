package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.session.Configuration;
import org.springframework.core.io.ClassPathResource;
import java.util.List;
import java.util.Map;
import org.mybatis.spring.annotation.MapperScannerRegistrar;
import org.mybatis.spring.mapper.MapperFactoryBean;
import org.mybatis.spring.mapper.MapperScannerConfigurer;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.type.AnnotationMetadata;
import top.egon.cola.component.outbox.autoconfigure.OutboxMybatisPlusAutoConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthMapperRegistrationTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "audit/OAuthAuditInboxMapper", "audit/OAuthAuditDeadLetterMapper", "audit/OAuthAuditReceiptMapper",
            "oauth/OAuthAuthenticationMapper", "oauth/OAuthInteractionMapper", "oauth/OAuthDeviceSessionMapper"})
    void auxiliaryMappersExposeTenantBoundActiveIdReads(String resourceName) throws Exception {
        var configuration = new Configuration();
        var resource = new ClassPathResource("mapper/" + resourceName + ".xml");
        try (var input = resource.getInputStream()) {
            new XMLMapperBuilder(input, configuration, resource.getPath(), configuration.getSqlFragments()).parse();
        }
        String mapper = resourceName.substring(resourceName.indexOf('/') + 1);
        String domain = resourceName.startsWith("audit/") ? "audit" : "oauth";
        String namespace = "top.egon.cola.platform.tianquan.shoubing.admin." + domain + ".dao." + mapper;
        for (String method : List.of("selectActiveById", "selectActiveByIds")) {
            var statement = configuration.getMappedStatement(namespace + '.' + method);
            var parameters = Map.of("tenantId", 1001L, "id", 2001L, "ids", List.of(2001L, 2002L));
            String sql = statement.getBoundSql(parameters).getSql().replaceAll("\\s+", " ").toLowerCase();
            assertThat(statement.getResource()).endsWith(".xml");
            assertThat(sql).contains("tenant_id = ?", "deleted_at is null");
            assertThat(statement.getBoundSql(parameters).getParameterMappings().getFirst().getProperty()).isEqualTo("tenantId");
        }
    }

    @Test
    void applicationMappersRemainRegisteredAlongsideTheOutboxScanner() {
        var registry = new DefaultListableBeanFactory();
        var registrar = new MapperScannerRegistrar();
        registrar.registerBeanDefinitions(AnnotationMetadata.introspect(OAuthPersistenceConfiguration.class), registry);
        registrar.registerBeanDefinitions(AnnotationMetadata.introspect(OutboxMybatisPlusAutoConfiguration.class), registry);
        try (var context = new GenericApplicationContext()) {
            context.refresh();
            for (String name : registry.getBeanNamesForType(MapperScannerConfigurer.class)) {
                var scanner = registry.getBean(name, MapperScannerConfigurer.class);
                scanner.setApplicationContext(context);
                scanner.postProcessBeanDefinitionRegistry(registry);
            }
            for (String mapper : new String[]{"OAuthRealmMapper", "OAuthClientMapper", "identityUserDAO",
                    "identityTenantDAO", "OAuthSigningKeyMapper", "outboxMessageDAO"}) {
                assertThat(registry.getBeanDefinition(mapper).getBeanClassName()).isEqualTo(MapperFactoryBean.class.getName());
            }
        }
    }
}
