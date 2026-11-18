package top.egon.cola.platform.tianquan.shoubing.admin.support.tianshu;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.MapPropertySource;
import top.egon.cola.component.tianshu.configdata.DdcConfigDataLoader;
import top.egon.cola.component.tianshu.configdata.DdcConfigDataResource;
import top.egon.cola.component.tianshu.format.DdcConfigCanonicalJson;
import top.egon.cola.component.tianshu.model.config.DdcConfigBaselineVO;
import top.egon.cola.component.tianshu.model.config.DdcConfigScopeVO;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DdcPolicyConfigTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Map<String, Long> VALUES = Map.of(
            AtomicIdpRuntimePolicy.ACCESS_TOKEN_TTL_KEY, 1200L,
            AtomicIdpRuntimePolicy.REFRESH_TOKEN_TTL_KEY, 172800L,
            AtomicIdpRuntimePolicy.AUTHORIZATION_CODE_TTL_KEY, 90L,
            AtomicIdpRuntimePolicy.MAXIMUM_LOGIN_FAILURES_KEY, 7L,
            AtomicIdpRuntimePolicy.LOGIN_LOCK_DURATION_KEY, 600L,
            AtomicIdpRuntimePolicy.PASSWORD_MAXIMUM_CONCURRENCY_KEY, 12L);

    @TempDir
    Path directory;

    @Test
    void localAndMigrationProfilesKeepDocumentedDefaultsWithoutRemoteConfiguration() {
        for (String profile : new String[]{"local", "oauth-migration"}) {
            runner().withPropertyValues("spring.profiles.active=" + profile).run(context -> {
                assertThat(context).hasNotFailed();
                var value = context.getBean(IdpRuntimePolicy.class).current();
                assertThat(value.accessTokenTtl()).isEqualTo(Duration.ofSeconds(900));
                assertThat(value.refreshTokenTtl()).isEqualTo(Duration.ofSeconds(604800));
                assertThat(value.authorizationCodeTtl()).isEqualTo(Duration.ofSeconds(60));
                assertThat(value.maximumLoginFailures()).isEqualTo(5);
                assertThat(value.loginLockDuration()).isEqualTo(Duration.ofSeconds(900));
                assertThat(value.passwordMaximumConcurrency()).isEqualTo(8);
                assertThat(value.configVersions()).hasSize(6).allSatisfy((key, version) -> assertThat(version).isZero());
            });
        }
    }

    @Test
    void localStartupBindsAllEffectiveValuesBeforePublishingThePolicyBean() {
        runner().withPropertyValues(properties(VALUES)).run(context -> {
            assertThat(context).hasNotFailed();
            assertValues(context.getBean(IdpRuntimePolicy.class).current());
        });
    }

    @Test
    void verifiedCloudBaselineBindsEveryRestartPolicyAndPinnedRevision() throws Exception {
        cloud(baseline()).run(context -> {
            assertThat(context).hasNotFailed();
            var value = context.getBean(IdpRuntimePolicy.class).current();
            assertValues(value);
            assertThat(value.configVersions()).hasSize(6).allSatisfy((key, version) -> assertThat(version).isEqualTo(43L));
        });
    }

    @Test
    void numericallyEquivalentHigherPriorityValueDoesNotBypassTheBaseline() throws Exception {
        cloud(baseline()).withPropertyValues(AtomicIdpRuntimePolicy.ACCESS_TOKEN_TTL_KEY + "=01200")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertValues(context.getBean(IdpRuntimePolicy.class).current());
                });
    }

    @Test
    void differentEffectiveValueIsRejectedBeforePolicyUse() throws Exception {
        cloud(baseline()).withPropertyValues(AtomicIdpRuntimePolicy.ACCESS_TOKEN_TTL_KEY + "=900")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void cloudProfileCannotStartWithoutVerifiedBaselineMetadata() {
        runner().withPropertyValues("spring.profiles.active=cloud-native")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void aSourceNamedLikeTheRestartSourceDoesNotProveVerification() {
        runner().withPropertyValues("spring.profiles.active=cloud-native")
                .withInitializer(context -> context.getEnvironment().getPropertySources().addLast(
                        new MapPropertySource(DdcConfigDataLoader.RESTART_PROPERTY_SOURCE_NAME, new LinkedHashMap<>(VALUES))))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void allSixPoliciesMustBePresentInRestartValuesEvenWhenRuleExists() throws Exception {
        for (String key : AtomicIdpRuntimePolicy.CONFIG_KEYS) {
            var document = baseline();
            ((ObjectNode) document.get("restartValues")).remove(key);
            cloud(document).run(context -> assertThat(context).hasFailed());
        }
    }

    @Test
    void noSecurityPolicyMayBeDeclaredHot() throws Exception {
        for (String key : AtomicIdpRuntimePolicy.CONFIG_KEYS) {
            var document = baseline();
            var value = ((ObjectNode) document.get("restartValues")).remove(key);
            ((ObjectNode) document.get("hotSeed")).set(key, value);
            document.withArray("rules").forEach(rule -> {
                if (rule.get("key").asText().equals(key)) ((ObjectNode) rule).put("mode", "HOT");
            });
            cloud(document).run(context -> assertThat(context).hasFailed());
        }
    }

    @Test
    void startupSnapshotCannotChangeWhenEnvironmentChangesLater() throws Exception {
        cloud(baseline()).run(context -> {
            assertThat(context).hasNotFailed();
            var policy = context.getBean(IdpRuntimePolicy.class);
            var initial = policy.current();
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("later-change",
                    Map.of(AtomicIdpRuntimePolicy.MAXIMUM_LOGIN_FAILURES_KEY, 19)));
            assertThat(policy.current()).isSameAs(initial);
            assertThat(policy.current().maximumLoginFailures()).isEqualTo(7);
            assertThatThrownBy(() -> initial.configVersions().put("injected", 4L))
                    .isInstanceOf(UnsupportedOperationException.class);
        });
    }

    @Test
    void startupValidationRetainsAllSixOriginalRangesAndRejectsOverflow() {
        Map<String, long[]> invalid = Map.of(
                AtomicIdpRuntimePolicy.ACCESS_TOKEN_TTL_KEY, new long[]{299, 1801},
                AtomicIdpRuntimePolicy.REFRESH_TOKEN_TTL_KEY, new long[]{86399, 2592001},
                AtomicIdpRuntimePolicy.AUTHORIZATION_CODE_TTL_KEY, new long[]{29, 301},
                AtomicIdpRuntimePolicy.MAXIMUM_LOGIN_FAILURES_KEY, new long[]{2, 21, Long.MAX_VALUE},
                AtomicIdpRuntimePolicy.LOGIN_LOCK_DURATION_KEY, new long[]{59, 3601},
                AtomicIdpRuntimePolicy.PASSWORD_MAXIMUM_CONCURRENCY_KEY, new long[]{0, 65, Long.MAX_VALUE});
        invalid.forEach((key, values) -> {
            for (long value : values) runner().withPropertyValues(key + "=" + value)
                    .run(context -> assertThat(context).hasFailed());
        });
    }

    @Test
    void malformedValuesAreRejectedWithoutRetainingRawInputInCauses() {
        for (String input : new String[]{"secret-value-must-not-be-logged", "-1", "+900", "9.0", "999999999999999999999999"}) {
            runner().withPropertyValues(AtomicIdpRuntimePolicy.ACCESS_TOKEN_TTL_KEY + "=" + input).run(context -> {
                assertThat(context).hasFailed();
                Throwable root = context.getStartupFailure();
                while (root.getCause() != null) root = root.getCause();
                assertThat(root).hasMessageNotContaining(input);
            });
        }
    }

    @Test
    void productionMutationAndLegacyAdapterClassesAreAbsent() {
        assertThat(Arrays.stream(AtomicIdpRuntimePolicy.class.getDeclaredMethods()).map(java.lang.reflect.Method::getName))
                .doesNotContain("apply", "set", "refresh");
        assertThatThrownBy(() -> Class.forName(IdpRuntimePolicy.class.getPackageName() + ".IdpDdcPolicyApplier"))
                .isInstanceOf(ClassNotFoundException.class);
        assertThatThrownBy(() -> Class.forName(IdpRuntimePolicy.class.getPackageName() + ".IdpDdcValueDeclarations"))
                .isInstanceOf(ClassNotFoundException.class);
    }

    private static ApplicationContextRunner runner() {
        return new ApplicationContextRunner().withUserConfiguration(DdcPolicyConfig.class)
                .withPropertyValues("egon.cola.component.tianshu.enabled=false");
    }

    private ApplicationContextRunner cloud(ObjectNode document) throws Exception {
        seal(document);
        Path folder = Files.createTempDirectory(directory, "baseline-");
        Path file = folder.resolve("baseline.json");
        Files.writeString(file, document.toString());
        var scope = new DdcConfigScopeVO("101", "identity", "test", "shoubing", "application.yml");
        var resource = new DdcConfigDataResource(file, scope,
                new DdcConfigDataResource.ExpectedTargetVO("shoubing-test", 3, "test-cluster", "identity", "workload-a", "application"));
        var loaded = new DdcConfigDataLoader().load(null, resource);
        return runner().withPropertyValues("spring.profiles.active=cloud-native").withInitializer(context -> {
            for (var source : loaded.getPropertySources()) context.getEnvironment().getPropertySources().addLast(source);
        });
    }

    private static ObjectNode baseline() throws Exception {
        var document = (ObjectNode) JSON.readTree("""
                {"schemaVersion":"1","scope":{"tenantId":"101","bizCode":"identity","env":"test",
                 "appCode":"shoubing","resourceName":"application.yml"},"source":{"configId":"42","revision":"43"},
                 "enabled":true,"contentSha256":"sha256:%s","restartDigest":"sha256:%s",
                 "rules":[],"targetBindings":[{"bindingId":"shoubing-test","bindingRevision":"3","clusterId":"test-cluster",
                 "kubernetesNamespace":"identity","workloadKind":"Deployment","workloadName":"shoubing","workloadUid":"workload-a","containerName":"application"}],
                 "restartValues":{},"hotSeed":{},"startupDependencies":{},"secretReferences":{}}
                """.formatted("0".repeat(64), "0".repeat(64)));
        VALUES.forEach((key, value) -> {
            ((ObjectNode) document.get("restartValues")).put(key, value);
            document.withArray("rules").addObject().put("key", key).put("mode", "RESTART").put("valueType", "INTEGER")
                    .putNull("schemaRef").put("nullable", false).put("deletionAllowed", false);
        });
        return document;
    }

    private static void seal(ObjectNode document) throws Exception {
        var value = JSON.treeToValue(document, DdcConfigBaselineVO.class);
        document.put("restartDigest", DdcConfigCanonicalJson.restartDigest(value));
        value = JSON.treeToValue(document, DdcConfigBaselineVO.class);
        document.put("contentSha256", DdcConfigCanonicalJson.contentSha256(value));
    }

    private static String[] properties(Map<String, Long> values) {
        return values.entrySet().stream().map(entry -> entry.getKey() + "=" + entry.getValue()).toArray(String[]::new);
    }

    private static void assertValues(IdpRuntimePolicy.Snapshot value) {
        assertThat(value.accessTokenTtl()).isEqualTo(Duration.ofSeconds(1200));
        assertThat(value.refreshTokenTtl()).isEqualTo(Duration.ofSeconds(172800));
        assertThat(value.authorizationCodeTtl()).isEqualTo(Duration.ofSeconds(90));
        assertThat(value.maximumLoginFailures()).isEqualTo(7);
        assertThat(value.loginLockDuration()).isEqualTo(Duration.ofSeconds(600));
        assertThat(value.passwordMaximumConcurrency()).isEqualTo(12);
    }
}
