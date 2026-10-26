package top.egon.cola.platform.tianquan.shoubing.yuheng.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.Set;

/**
 * 描述 Gateway 接入统一 Tianquan-Shoubing 时使用的验证与运行时配置。
 * 可信路由仅选择目标 Resource；JWT、实时状态和审计复用 Starter 的数据库权威链。
 *
 * <p>Describes verification and runtime settings for integrating the Gateway with the unified Tianquan-Shoubing.
 * Trusted routes select the expected Resource; verification and audit reuse the shared SQL authority pipeline.</p>
 */
@ConfigurationProperties("egon.cola.platform.tianquan.shoubing.yuheng")
public class IdpGatewayAdapterProperties {

    /**
     * 是否启用 Gateway Tianquan-Shoubing 适配器。
     *
     * <p>Whether the Gateway Tianquan-Shoubing adapter is enabled.</p>
     */
    private boolean enabled;

    private String tianquanShoubingRefreshUri;

    private String accessTokenCookieName = "__Host-egon_user_at";

    private String refreshTokenCookieName = "__Host-egon_user_rt";

    private URI refreshStatusResourceUri;

    private Set<String> refreshStatusScopes = Set.of(
            "tianquan-shoubing:refresh-token:validate");

    private java.util.Set<String> trustedOrigins = java.util.Set.of();

    private java.util.Map<String, RouteResource> routeResources = new java.util.LinkedHashMap<>();

    public java.util.Map<String, RouteResource> getRouteResources() { return routeResources; }
    public void setRouteResources(java.util.Map<String, RouteResource> value) { routeResources = value; }

    /** Trusted target selection only; authority state is never copied into deployment configuration. */
    public static class RouteResource {
        private String bizCode;
        private String appCode;
        private String environment;
        private URI resourceUri;
        public String getBizCode() { return bizCode; }
        public void setBizCode(String value) { bizCode = value; }
        public String getAppCode() { return appCode; }
        public void setAppCode(String value) { appCode = value; }
        public String getEnvironment() { return environment; }
        public void setEnvironment(String value) { environment = value; }
        public URI getResourceUri() { return resourceUri; }
        public void setResourceUri(URI value) { resourceUri = value; }
    }

    /**
     * 创建使用默认值初始化的 Gateway Tianquan-Shoubing 适配器配置。
     *
     * <p>Creates Gateway Tianquan-Shoubing adapter settings initialized with their defaults.</p>
     */
    public IdpGatewayAdapterProperties() {
    }

    /**
     * 返回是否启用适配器。
     *
     * <p>Returns whether the adapter is enabled.</p>
     *
     * @return {@code true} 表示启用；{@code true} when enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 设置是否启用适配器。
     *
     * <p>Sets whether the adapter is enabled.</p>
     *
     * @param enabled 是否启用；whether to enable the adapter
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getTianquanShoubingRefreshUri() {
        return tianquanShoubingRefreshUri;
    }

    public void setTianquanShoubingRefreshUri(String tianquanShoubingRefreshUri) {
        this.tianquanShoubingRefreshUri = tianquanShoubingRefreshUri;
    }

    public String getAccessTokenCookieName() {
        return accessTokenCookieName;
    }

    public void setAccessTokenCookieName(String accessTokenCookieName) {
        this.accessTokenCookieName = accessTokenCookieName;
    }

    public String getRefreshTokenCookieName() {
        return refreshTokenCookieName;
    }

    public void setRefreshTokenCookieName(String refreshTokenCookieName) {
        this.refreshTokenCookieName = refreshTokenCookieName;
    }

    public URI getRefreshStatusResourceUri() {
        return refreshStatusResourceUri;
    }

    public void setRefreshStatusResourceUri(URI refreshStatusResourceUri) {
        this.refreshStatusResourceUri = refreshStatusResourceUri;
    }

    public Set<String> getRefreshStatusScopes() {
        return refreshStatusScopes;
    }

    public void setRefreshStatusScopes(Set<String> refreshStatusScopes) {
        this.refreshStatusScopes = refreshStatusScopes;
    }

    public java.util.Set<String> getTrustedOrigins() {
        return trustedOrigins;
    }

    public void setTrustedOrigins(java.util.Set<String> trustedOrigins) {
        this.trustedOrigins = trustedOrigins == null
                ? java.util.Set.of()
                : java.util.Set.copyOf(trustedOrigins);
    }

    /**
     * 校验启用 Gateway Tianquan-Shoubing 验证所必需的配置。
     *
     * <p>Validates settings required to enable Gateway Tianquan-Shoubing verification.</p>
     *
     * @throws IllegalStateException 当必要配置缺失或集合包含空值时；when a required setting is
     *                               missing or a configured set contains a blank value
     */
    public void validate() {
        required(accessTokenCookieName, "accessTokenCookieName");
        required(refreshTokenCookieName, "refreshTokenCookieName");
    }

    /**
     * 校验单个文本配置不为空。
     *
     * <p>Validates that a scalar text setting is not blank.</p>
     *
     * @param value 配置值；setting value
     * @param field 配置字段名；setting field name
     * @throws IllegalStateException 当配置为空时；when the setting is blank
     */
    private void required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "egon.cola.platform.tianquan.shoubing.yuheng." + field + " is required");
        }
    }

    private void resource(URI value, String field) {
        if (value == null || !value.isAbsolute()
                || value.getFragment() != null
                || !value.equals(value.normalize())) {
            throw new IllegalStateException(
                    "egon.cola.platform.tianquan.shoubing.yuheng." + field
                            + " must be an absolute normalized URI without a fragment");
        }
    }

}
