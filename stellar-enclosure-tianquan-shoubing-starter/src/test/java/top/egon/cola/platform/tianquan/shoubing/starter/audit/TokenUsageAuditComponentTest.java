package top.egon.cola.platform.tianquan.shoubing.starter.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.*;

import java.net.URI;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;

class TokenUsageAuditComponentTest {
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private final IdentityAuthorityClient client = mock(IdentityAuthorityClient.class);
    private final IdentityAuthorityClientResolver resolver = mock(IdentityAuthorityClientResolver.class);
    private TokenUsageAuditComponent component;

    @BeforeEach void prepare() {
        validator.afterPropertiesSet();
        when(resolver.forResource(event().issuer(), URI.create(event().resource()))).thenReturn(client);
        component = new TokenUsageAuditComponent(resolver, Clock.fixed(event().occurredAt(), ZoneOffset.UTC), validator,
                IdpSecurityMetricsRecorder.NOOP);
    }
    @AfterEach void close() { validator.close(); }

    @Test void exactSqlReceiptCompletesEachHandoffWithoutLocalState() {
        var receipt = receipt(event()); when(client.appendAudit(event())).thenReturn(receipt);
        assertThat(component.appendStrict(event())).isSameAs(receipt);
        assertThat(component.append(event())).isSameAs(receipt);
        verify(client, times(2)).appendAudit(event()); verify(resolver, times(2)).forResource(event().issuer(), URI.create(event().resource()));
    }

    @Test void missingOrMismatchedSqlReceiptNeverConfirmsDelivery() {
        var good = receipt(event());
        var invalid = List.of(
                new IdentityAuditReceipt("bad", good.eventId(), good.eventFingerprint(), good.sourceIssuer(), good.sourceClientId(), good.resource(), good.outcome(), good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), "other", good.eventFingerprint(), good.sourceIssuer(), good.sourceClientId(), good.resource(), good.outcome(), good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), "0".repeat(64), good.sourceIssuer(), good.sourceClientId(), good.resource(), good.outcome(), good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), "https://other.example", good.sourceClientId(), good.resource(), good.outcome(), good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), good.sourceIssuer(), "", good.resource(), good.outcome(), good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), good.sourceIssuer(), good.sourceClientId(), "https://other.example", good.outcome(), good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), good.sourceIssuer(), good.sourceClientId(), good.resource(), "STAGED", good.confirmedAt()),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), good.sourceIssuer(), good.sourceClientId(), good.resource(), good.outcome(), null),
                new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), good.sourceIssuer(), good.sourceClientId(), good.resource(), good.outcome(), good.confirmedAt().plusSeconds(61)));
        for (var receipt : invalid) {
            when(client.appendAudit(any())).thenReturn(receipt);
            assertThatThrownBy(() -> component.appendStrict(event())).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
        }
        when(client.appendAudit(any())).thenReturn(null);
        assertThatThrownBy(() -> component.appendStrict(event())).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
    }

    @Test void authorityFailureAndUntrustedIssuerFailClosedWithoutRetryingLocally() {
        when(client.appendAudit(any())).thenThrow(new IllegalStateException("controlled SQL unavailable"));
        assertThatThrownBy(() -> component.append(event())).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
        verify(client).appendAudit(event());
        when(resolver.forResource(any(), any())).thenThrow(new IllegalStateException("untrusted"));
        assertThatThrownBy(() -> component.appendStrict(event())).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
    }

    @Test void referenceIsIssuerBoundAndDoesNotRequireAFileKey() {
        String reference = component.reference(event().issuer(), "901");
        assertThat(reference).matches("[a-f0-9]{64}").isEqualTo(component.reference(event().issuer(), "901"));
        assertThat(reference).isNotEqualTo(component.reference(URI.create("https://idp.example/tenants/1002"), "901"));
        assertThatThrownBy(() -> component.reference(event().issuer(), "raw-token")).isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(client, resolver);
    }
}
