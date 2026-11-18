package top.egon.cola.platform.tianquan.shoubing.starter.client;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Transport;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdpTransportBindingRegistryTest {

    private static final URI ISSUER = URI.create("https://identity.example/issuer/tenant");
    private static final URI TOKEN = URI.create("https://identity.example/oauth2/token");
    private static final URI AUDIENCE = URI.create("https://orders.example");
    private static final String REGISTRATION = "orders-service";

    @Test
    void derivesOnlyTheConfiguredServiceAndPreservesCanonicalIdentity() {
        var binding = tokenBinding("orders-token", 2, "token", "identity", TOKEN);
        var registry = new IdpTransportBindingRegistry(List.of(binding));
        assertThat(registry.select(ISSUER, TOKEN, AUDIENCE, REGISTRATION, Operation.TOKEN, "POST"))
                .containsSame(binding);
        assertThat(binding.canonicalIssuer()).isEqualTo(ISSUER);
        assertThat(binding.canonicalEndpoint()).isEqualTo(TOKEN);
        assertThat(binding.resource()).isEqualTo(AUDIENCE);
        assertThat(binding.physicalUri()).isEqualTo(
                URI.create("http://token.identity.svc.cluster.local:18080/oauth2/token"));
        assertThat(registry.select(ISSUER, TOKEN, AUDIENCE, "other-service", Operation.TOKEN, "POST"))
                .isEmpty();
    }

    @Test
    void anOptedInRegistrationCannotFallBackWhenItsOperationOrCanonicalIdentityDoesNotMatch() {
        URI canonicalResolve = URI.create("https://identity.example/internal/resolve");
        var entry = new IdpTransportBindingVO("authority-resolve", 1, ISSUER, canonicalResolve,
                AUDIENCE, REGISTRATION, Operation.AUTHORITY_RESOLVE, "POST", "/internal/resolve",
                "identity", "authority", 18100, Transport.HTTP);
        var registry = new IdpTransportBindingRegistry(List.of(entry));

        assertThat(registry.hasBindings(REGISTRATION, Operation.AUTHORITY_AUDIT)).isTrue();
        assertThatThrownBy(() -> registry.select(ISSUER, canonicalResolve, AUDIENCE, REGISTRATION,
                Operation.AUTHORITY_AUDIT, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
        assertThatThrownBy(() -> registry.select(ISSUER, canonicalResolve, AUDIENCE, REGISTRATION,
                Operation.AUTHORITY_RESOLVE, "GET")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
        assertThatThrownBy(() -> registry.select(ISSUER, entry.physicalUri(), AUDIENCE, REGISTRATION,
                Operation.AUTHORITY_RESOLVE, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
        assertThatThrownBy(() -> registry.select(ISSUER, canonicalResolve, URI.create("https://wrong.example"),
                REGISTRATION, Operation.AUTHORITY_RESOLVE, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
        assertThatThrownBy(() -> registry.select(URI.create("https://forged.example"), canonicalResolve, AUDIENCE,
                REGISTRATION, Operation.AUTHORITY_RESOLVE, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
    }

    @Test
    void rejectsDuplicateIdentityAndConfiguredVersionMismatches() {
        var current = tokenBinding("orders-token", 3, "token", "identity", TOKEN);
        var sameVersionDifferentService = tokenBinding("orders-token", 3, "other", "identity", TOKEN);
        assertThatThrownBy(() -> new IdpTransportBindingRegistry(List.of(current, sameVersionDifferentService)))
                .hasMessage("IDP_TRANSPORT_BINDING_CONFLICT");
        assertThatThrownBy(() -> new IdpTransportBindingRegistry(
                List.of(current, tokenBinding("different-id", 3, "token", "identity", TOKEN))))
                .hasMessage("IDP_TRANSPORT_BINDING_CONFLICT");
        var registry = new IdpTransportBindingRegistry(List.of(current));
        assertThat(registry.require("orders-token", 3, ISSUER, TOKEN, AUDIENCE, REGISTRATION, Operation.TOKEN, "POST"))
                .isSameAs(current);
        assertThatThrownBy(() -> registry.require("orders-token", 2, ISSUER, TOKEN, AUDIENCE, REGISTRATION,
                Operation.TOKEN, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
        assertThatThrownBy(() -> registry.require("missing", 3, ISSUER, TOKEN, AUDIENCE, REGISTRATION,
                Operation.TOKEN, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
        assertThatThrownBy(() -> registry.require("orders-token", 3, ISSUER, TOKEN, AUDIENCE, "wrong",
                Operation.TOKEN, "POST")).hasMessage("IDP_TRANSPORT_BINDING_MISMATCH");
    }

    @Test
    void rejectsIpOrArbitraryTargetAndAmbiguousCanonicalPaths() {
        assertThatThrownBy(() -> tokenBinding("orders-token", 1, "127.0.0.1", "identity", TOKEN))
                .hasMessage("IDP_TRANSPORT_BINDING_INVALID");
        assertThatThrownBy(() -> tokenBinding("orders-token", 1, "token.external.example", "identity", TOKEN))
                .hasMessage("IDP_TRANSPORT_BINDING_INVALID");
        assertThatThrownBy(() -> tokenBinding("orders-token", 1, "token", "identity",
                URI.create("https://identity.example/oauth2/%2e/token")))
                .hasMessage("IDP_TRANSPORT_BINDING_INVALID");
        assertThatThrownBy(() -> tokenBinding("orders-token", 1, "token", "identity",
                URI.create("https://identity.example/oauth2/token?receiver=elsewhere")))
                .hasMessage("IDP_TRANSPORT_BINDING_INVALID");
        assertThatThrownBy(() -> new IdpTransportBindingVO("orders-token", 1, ISSUER, TOKEN,
                URI.create("http://orders.example"), REGISTRATION, Operation.TOKEN, "POST", TOKEN.getRawPath(),
                "identity", "token", 18080, Transport.HTTP)).hasMessage("IDP_TRANSPORT_BINDING_INVALID");
        assertThatThrownBy(() -> new IdpTransportBindingVO("orders-token", 1, ISSUER, TOKEN,
                AUDIENCE, REGISTRATION, Operation.TOKEN, "POST", "/unexpected", "identity", "token", 18080,
                Transport.HTTP)).hasMessage("IDP_TRANSPORT_BINDING_INVALID");
        assertThatThrownBy(() -> new IdpTransportBindingVO("orders-token", 1, ISSUER, TOKEN,
                AUDIENCE, REGISTRATION, Operation.TOKEN, "POST", TOKEN.getRawPath(), "identity", "token", 18080,
                Transport.H2C)).hasMessage("IDP_TRANSPORT_BINDING_INVALID");
    }

    @Test
    void freezesTheProjectedDestinationsIndependentlyOfMutableDeploymentProperties() {
        String prefix = "egon.cola.platform.tianquan.shoubing.transport";
        var values = new LinkedHashMap<String, Object>();
        Map.ofEntries(
                Map.entry("version", 1), Map.entry("canonical-issuer", ISSUER.toString()),
                Map.entry("canonical-endpoint", TOKEN.toString()), Map.entry("resource", AUDIENCE.toString()),
                Map.entry("registration-id", REGISTRATION), Map.entry("operation", "TOKEN"),
                Map.entry("method", "POST"), Map.entry("path", "/oauth2/token"),
                Map.entry("namespace", "identity"), Map.entry("service", "token"),
                Map.entry("port", 18080), Map.entry("transport", "HTTP"))
                .forEach((field, value) -> values.put(prefix + ".bindings.orders-token." + field, value));
        var properties = new Binder(new MapConfigurationPropertySource(values))
                .bind(prefix, Bindable.of(IdpTransportBindingProperties.class)).get();
        var registry = new IdpTransportBindingRegistry(properties, IdpTransportBindingConverter.INSTANCE);

        properties.getBindings().get("orders-token").setService("replacement");
        properties.getBindings().clear();
        assertThat(registry.select(ISSUER, TOKEN, AUDIENCE, REGISTRATION, Operation.TOKEN, "POST")
                .orElseThrow().physicalUri().getHost()).isEqualTo("token.identity.svc.cluster.local");
    }

    private static IdpTransportBindingVO tokenBinding(
            String bindingId, long version, String service, String namespace, URI endpoint) {
        return new IdpTransportBindingVO(bindingId, version, ISSUER, endpoint, AUDIENCE, REGISTRATION,
                Operation.TOKEN, "POST", endpoint.getRawPath(), namespace, service, 18080, Transport.HTTP);
    }
}
