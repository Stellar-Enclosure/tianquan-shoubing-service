package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;

@Configuration(proxyBeanMethods = false)
public class OAuthAuthoritySecurityConfiguration {

    @Bean("oauthAuthoritySecurityFilterChain")
    @Order(0)
    SecurityFilterChain authorityChain(HttpSecurity http,
            @Qualifier("oauthAuthorityService") OAuthAuthorityService service,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper) throws Exception {
        return http.securityMatcher("/internal/v1/identity/security-state:resolve", "/internal/v1/identity/audit-events")
                .sessionManagement(value -> value.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(value -> value.securityContextRepository(new NullSecurityContextRepository()))
                .requestCache(value -> value.requestCache(new NullRequestCache()))
                .csrf(value -> value.disable()).formLogin(value -> value.disable()).httpBasic(value -> value.disable())
                .logout(value -> value.disable())
                .authorizeHttpRequests(value -> value.anyRequest().authenticated())
                .addFilterBefore(new OAuthAuthorityAuthenticationFilter(service, mapper), AnonymousAuthenticationFilter.class)
                .build();
    }
}
