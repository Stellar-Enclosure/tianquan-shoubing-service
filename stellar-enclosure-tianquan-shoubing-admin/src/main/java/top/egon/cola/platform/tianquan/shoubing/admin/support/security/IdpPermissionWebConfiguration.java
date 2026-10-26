package top.egon.cola.platform.tianquan.shoubing.admin.support.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import top.egon.cola.platform.tianquan.jianshen.starter.field.PermissionJsonMapperFactory;
import java.util.List;

/** Field policy is installed only on HTTP mapper copies; native OAuth and SQL codecs keep their original mapper. */
@Configuration(proxyBeanMethods=false)
@ConditionalOnProperty(prefix="egon.cola.platform.tianquan.jianshen",name="enabled",havingValue="true")
public class IdpPermissionWebConfiguration implements WebMvcConfigurer {
    private final PermissionJsonMapperFactory fields;
    public IdpPermissionWebConfiguration(PermissionJsonMapperFactory fields) { this.fields=fields; }
    @Override public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        for(var converter:converters) if(converter instanceof MappingJackson2HttpMessageConverter json) {
            json.setObjectMapper(fields.forTransport(json.getObjectMapper()));
        }
    }
}
