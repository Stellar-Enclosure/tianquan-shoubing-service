package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import top.egon.cola.platform.tianquan.shoubing.admin.token.config.OAuthKeyEncryptionProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.token.config.OAuthRevocationProperties;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthSqlAuthorityPropertyScanTest {
    @Test
    void normalConfigurationScanDoesNotRequireRetiredRedisRevocationProperties() {
        new ApplicationContextRunner().withUserConfiguration(SqlAuthorityConfiguration.class)
                .withPropertyValues("egon.tianquan-shoubing.oauth.key-encryption.key-id=isolated-test",
                        "egon.tianquan-shoubing.oauth.key-encryption.key-file=/isolated/not-opened")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(OAuthKeyEncryptionProperties.class)
                            .doesNotHaveBean(OAuthRevocationProperties.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @ConfigurationPropertiesScan(basePackageClasses = OAuthKeyEncryptionProperties.class)
    static class SqlAuthorityConfiguration { }
}
