package top.egon.cola.platform.tianquan.shoubing.admin.support.tianshu;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.Profiles;
import top.egon.cola.component.tianshu.configdata.DdcConfigDataLoader;
import top.egon.cola.component.tianshu.model.config.DdcConfigBaselineVO;

import java.util.LinkedHashMap;
import java.util.Map;

/** Binds security policy from verified immutable RESTART values before the application can serve requests. */
@Configuration(proxyBeanMethods = false)
public class DdcPolicyConfig {

    @Bean
    @Lazy(false)
    AtomicIdpRuntimePolicy idpRuntimePolicy(ConfigurableEnvironment environment) {
        var metadata = DdcConfigDataLoader.baselineMetadataOrNull(environment);
        var restartSource = environment.getPropertySources().get(DdcConfigDataLoader.RESTART_PROPERTY_SOURCE_NAME);
        boolean baselineRequired = environment.acceptsProfiles(Profiles.of("cloud-native"))
                || Boolean.TRUE.equals(environment.getProperty("egon.cola.component.tianshu.delivery.enabled", Boolean.class))
                || environment.containsProperty("egon.cola.component.tianshu.baseline.file")
                || restartSource != null;
        if (metadata == null && baselineRequired) {
            throw new IllegalStateException("IDP_POLICY_VERIFIED_BASELINE_REQUIRED");
        }

        Map<String, DdcConfigBaselineVO.RuleVO> rules = new LinkedHashMap<>();
        if (metadata != null) {
            metadata.rules().forEach(rule -> rules.put(rule.getKey(), rule));
            if (!(restartSource instanceof MapPropertySource)) {
                throw new IllegalStateException("IDP_POLICY_RESTART_VALUES_REQUIRED");
            }
        }

        Map<String, Long> values = new LinkedHashMap<>();
        for (String key : AtomicIdpRuntimePolicy.CONFIG_KEYS) {
            Object effective = effectiveValue(environment, key);
            if (metadata == null) {
                values.put(key, effective == null ? AtomicIdpRuntimePolicy.defaultValue(key)
                        : AtomicIdpRuntimePolicy.numericValue(effective));
                continue;
            }
            var rule = rules.get(key);
            if (rule == null || rule.getMode() != DdcConfigBaselineVO.ReloadModeEnum.RESTART
                    || !restartSource.containsProperty(key) || restartSource.getProperty(key) == null) {
                throw new IllegalStateException("IDP_POLICY_RESTART_VALUES_REQUIRED");
            }
            long fixedValue = AtomicIdpRuntimePolicy.numericValue(restartSource.getProperty(key));
            if (effective == null || AtomicIdpRuntimePolicy.numericValue(effective) != fixedValue) {
                throw new IllegalStateException("IDP_POLICY_EFFECTIVE_VALUE_MISMATCH");
            }
            values.put(key, fixedValue);
        }
        long revision = metadata == null ? 0L : Long.parseLong(metadata.source().getRevision());
        return new AtomicIdpRuntimePolicy(values, revision);
    }

    private static Object effectiveValue(ConfigurableEnvironment environment, String key) {
        try {
            return environment.getProperty(key, Object.class);
        } catch (RuntimeException invalid) {
            // Placeholder/conversion errors must not retain deployment values or credential-like input.
            throw new IllegalArgumentException("IDP_POLICY_INTEGER_INVALID");
        }
    }
}
