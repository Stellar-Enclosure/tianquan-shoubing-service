package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import com.baomidou.mybatisplus.core.MybatisConfiguration;
import com.baomidou.mybatisplus.core.config.GlobalConfig;
import com.baomidou.mybatisplus.spring.MybatisSqlSessionFactoryBean;
import java.time.Instant;
import java.util.List;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.session.RowBounds;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.context.annotation.CommonAnnotationBeanPostProcessor;
import org.springframework.core.io.ClassPathResource;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaTenantIdGuardInnerInterceptor;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthAuthorizationMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthAuthorizationPO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

class OAuthAuthorizationInsertMappingTest {
    private static final Instant NOW = Instant.parse("2026-11-22T00:00:00Z");
    private static final String ACTOR = "service:tianquan-shoubing";

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void generatedInsertKeepsDeviceSessionAndRefreshGenerationDistinct(boolean sessionAlreadyAssigned) throws Exception {
        var configuration = new MybatisConfiguration();
        configuration.setMapUnderscoreToCamelCase(true);
        var global = new GlobalConfig();
        global.setDbConfig(new GlobalConfig.DbConfig());
        var factory = new MybatisSqlSessionFactoryBean();
        factory.setConfiguration(configuration);
        factory.setGlobalConfig(global);
        factory.setDataSource(mock(javax.sql.DataSource.class));
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthAuthorizationMapper.xml"));
        configuration = (MybatisConfiguration) factory.getObject().getConfiguration();
        var row = OAuthAuthorizationPO.builder().id(77L).tenantId(1001L).version(0L)
                .createUserId(ACTOR).createTime(NOW).updateUserId(ACTOR).updateTime(NOW)
                .clientPk(501L).principalName("alice").principalType("USER").grantType("authorization_code")
                .authorizedScopes(List.of("openid")).requestedScopes(List.of("openid"))
                .audiences(List.of("https://api.example/orders")).resourceUri("https://api.example/orders")
                .status(sessionAlreadyAssigned ? "ACTIVE" : "PENDING_CONSENT").attributesCiphertext("encrypted")
                .absoluteExpiresAt(NOW.plusSeconds(300)).retainUntil(NOW.plusSeconds(86_700))
                .deviceSessionId(sessionAlreadyAssigned ? 701L : null).refreshGeneration(0L).build();
        var statement = configuration.getMappedStatement(OAuthAuthorizationMapper.class.getName() + ".insert");
        var bound = statement.getBoundSql(row);
        var handler = configuration.newStatementHandler(mock(Executor.class), statement,
                row, RowBounds.DEFAULT, null, bound);
        var guard = new EgonColaTenantIdGuardInnerInterceptor(() -> ACTOR, new EgonColaMybatisPlusProperties());
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(guard, "sqlGuard");
        var routeGuard = new top.egon.cola.component.common.mybatis.interceptor.EgonColaLocalWriteGuardInnerInterceptor(
                query -> new top.egon.cola.component.common.mybatis.routing.EgonColaRouteResult(
                        List.of(new top.egon.cola.component.common.mybatis.routing.EgonColaPhysicalTargetBO(
                                "primary", "tianquan_oauth", "oauth_authorization")), "a".repeat(64)),
                guard, mock(top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy.class), java.util.Map.of());
        MDC.put("tenantId", "1001");
        MDC.put("userId", ACTOR);
        try {
            assertThatCode(() -> {
                guard.beforePrepare(handler, null, null);
                routeGuard.beforePrepare(handler, null, null);
            }).doesNotThrowAnyException();
            var insert = (net.sf.jsqlparser.statement.insert.Insert)
                    net.sf.jsqlparser.parser.CCJSqlParserUtil.parse(bound.getSql());
            var columns = insert.getColumns().stream().map(column -> column.getColumnName()).toList();
            assertThat(columns).doesNotHaveDuplicates().contains("refresh_generation");
            assertThat(bound.getParameterMappings().get(columns.indexOf("refresh_generation")).getProperty())
                    .isEqualTo("refreshGeneration");
            if (sessionAlreadyAssigned) {
                assertThat(columns).contains("device_session_id");
                assertThat(bound.getParameterMappings().get(columns.indexOf("device_session_id")).getProperty())
                        .isEqualTo("deviceSessionId");
            } else {
                assertThat(columns).doesNotContain("device_session_id");
            }
        } finally {
            MDC.remove("tenantId");
            MDC.remove("userId");
        }
    }
}
