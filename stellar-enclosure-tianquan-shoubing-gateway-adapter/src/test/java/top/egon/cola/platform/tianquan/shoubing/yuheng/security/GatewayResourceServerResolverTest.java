package top.egon.cola.platform.tianquan.shoubing.yuheng.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.yuheng.autoconfigure.IdpGatewayAdapterProperties;

class GatewayResourceServerResolverTest {
    private static final URI RESOURCE = URI.create("https://api.example/orders");

    @Test void exactBusinessApplicationEnvironmentSelectsOnlyTheBoundTarget() {
        var resolver = resolver();
        assertThat(resolver.resolve(Map.of("tianquan-shoubing.biz-code", "commerce", "tianquan-shoubing.app-code", "orders",
                "tianquan-shoubing.env", "test"))).isEqualTo(RESOURCE);
        assertThatThrownBy(() -> resolver.resolve(Map.of("tianquan-shoubing.biz-code", "commerce",
                "tianquan-shoubing.app-code", "other", "tianquan-shoubing.env", "test"))).hasMessage("TIANQUAN_SHOUBING_RESOURCE_NOT_BOUND");
        assertThatThrownBy(() -> resolver.resolve(Map.of("tianquan-shoubing.biz-code", "commerce")))
                .hasMessage("TIANQUAN_SHOUBING_RESOURCE_ROUTE_INVALID");
    }

    @Test void mcpTargetMustBeBoundAndCannotOverrideAConflictingRoute() {
        var resolver = resolver();
        assertThat(resolver.resolve(Map.of("tianquan-shoubing.resource-uri", RESOURCE.toASCIIString()))).isEqualTo(RESOURCE);
        assertThatThrownBy(() -> resolver.resolve(Map.of("tianquan-shoubing.resource-uri", "https://unbound.example")))
                .hasMessage("TIANQUAN_SHOUBING_RESOURCE_NOT_BOUND");
        assertThatThrownBy(() -> resolver.resolve(Map.of("tianquan-shoubing.resource-uri", "https://api.example/other",
                "tianquan-shoubing.biz-code", "commerce", "tianquan-shoubing.app-code", "orders", "tianquan-shoubing.env", "test")))
                .hasMessage("TIANQUAN_SHOUBING_RESOURCE_ROUTE_MISMATCH");
        assertThatThrownBy(() -> resolver.resolve(Map.of("Authorization", "Bearer forged", "X-Resource-Uri", RESOURCE.toASCIIString())))
                .hasMessage("TIANQUAN_SHOUBING_RESOURCE_ROUTE_INVALID");
    }

    @Test void invalidOrDuplicateBindingsFailBeforeAnyRequest() {
        assertThatThrownBy(() -> new GatewayResourceServerResolver(Map.of())).hasMessage("GATEWAY_RESOURCE_BINDINGS_REQUIRED");
        var first = binding(RESOURCE); var second = binding(URI.create("https://api.example/other"));
        assertThatThrownBy(() -> new GatewayResourceServerResolver(Map.of("first", first, "second", second)))
                .hasMessage("GATEWAY_RESOURCE_ROUTE_DUPLICATE");
        first.setAppCode(null);
        assertThatThrownBy(() -> new GatewayResourceServerResolver(Map.of("first", first)))
                .hasMessage("GATEWAY_ROUTE_IDENTIFIER_INVALID");
    }

    static GatewayResourceServerResolver resolver() {
        var other = new IdpGatewayAdapterProperties.RouteResource(); other.setResourceUri(URI.create("https://api.example/other"));
        return new GatewayResourceServerResolver(Map.of("orders", binding(RESOURCE), "other", other));
    }
    private static IdpGatewayAdapterProperties.RouteResource binding(URI resource) {
        var value = new IdpGatewayAdapterProperties.RouteResource(); value.setResourceUri(resource);
        value.setBizCode("commerce"); value.setAppCode("orders"); value.setEnvironment("test"); return value;
    }
}
