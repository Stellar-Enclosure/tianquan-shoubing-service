package top.egon.cola.platform.tianquan.shoubing.admin.openapi;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.egon.cola.component.yuheng.openapi.config.GatewayOpenApiProperties;
import top.egon.cola.component.yuheng.openapi.customizer.EgonOpenApiCustomizer;
import top.egon.cola.component.yuheng.openapi.customizer.EgonOperationCustomizer;

/** Serves the read-only catalog from the application without a provider registration contributor. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "egon.cola.component.yuheng.openapi", name = "enabled", havingValue = "true")
public class IdpCatalogOpenApiConfiguration {

    @Bean("gatewayOpenApiProperties")
    @ConfigurationProperties("egon.cola.component.yuheng.openapi")
    GatewayOpenApiProperties gatewayOpenApiProperties() {
        var properties = new GatewayOpenApiProperties();
        properties.setPublishToDdc(false);
        return properties;
    }

    @Bean("egonOperationCustomizer")
    EgonOperationCustomizer egonOperationCustomizer(
            @Qualifier("gatewayOpenApiProperties") GatewayOpenApiProperties properties) {
        return new EgonOperationCustomizer(properties);
    }

    @Bean("egonOpenApiCustomizer")
    EgonOpenApiCustomizer egonOpenApiCustomizer(
            @Qualifier("gatewayOpenApiProperties") GatewayOpenApiProperties properties) {
        return new EgonOpenApiCustomizer(properties);
    }
}
