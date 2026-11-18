package top.egon.cola.platform.tianquan.shoubing.starter.client;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Transport;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/** Deployment-owned alternatives to the public HTTPS transport for exact internal operations. */
@Data
@Validated
@ConfigurationProperties(prefix = "egon.cola.platform.tianquan.shoubing.transport", ignoreUnknownFields = false)
public class IdpTransportBindingProperties {

    @NotNull
    @Size(max = 512)
    private Map<@NotBlank String, @NotNull @Valid Binding> bindings = new LinkedHashMap<>();

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder(toBuilder = true)
    public static class Binding {
        private String bindingId;
        @Positive
        private long version;
        @NotNull
        private URI canonicalIssuer;
        @NotNull
        private URI canonicalEndpoint;
        @NotNull
        private URI resource;
        @NotBlank
        private String registrationId;
        @NotNull
        private Operation operation;
        @NotBlank
        private String method;
        @NotBlank
        private String path;
        @NotBlank
        private String namespace;
        @NotBlank
        private String service;
        @Positive
        private int port;
        @NotNull
        private Transport transport;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Reference {
        @NotBlank
        private String bindingId;
        @Positive
        private long version;
    }
}
