package top.egon.cola.platform.tianquan.shoubing.admin.audit.support.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.outbox.delivery.DeliveryContext;
import top.egon.cola.component.outbox.delivery.DeliveryResult;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthAuditOutboxDeliveryHandlerTest {
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final OAuthAuditRepository audits = mock(OAuthAuditRepository.class);
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthAuditOutboxDeliveryHandler handler = new OAuthAuditOutboxDeliveryHandler(audits, issuers, mapper);
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final Instant NOW = Instant.parse("2026-10-23T00:00:00Z");

    @Test void succeedsOnlyAfterConfirmedOwnerDatabaseSave() throws Exception {
        var realm = TrustedRealmBO.builder().issuer(ISSUER).build();
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(realm);
        when(audits.save(eq(realm), any(), eq(0L))).thenAnswer(call -> ((OAuthAuditBO) call.getArgument(1)).setId(11L));
        assertEquals(DeliveryResult.Kind.SUCCESS, handler.deliver(context(event())).kind());
        verify(audits).save(eq(realm), argThat(value -> "CLIENT_CREDENTIALS_TOKEN_ISSUED".equals(value.getEventType())
                && "https://api.example/orders".equals(value.getResourceRef())), eq(0L));
    }

    @Test void secretOrUnlistedFieldNeverReachesDatabase() throws Exception {
        var event = event(); event.put("token", "do-not-persist");
        assertEquals(DeliveryResult.Kind.PERMANENT_FAILURE, handler.deliver(context(event)).kind());
        verifyNoInteractions(audits, issuers);
    }

    @Test void databaseFailureRemainsRetryableWithoutAnotherDeliveryStore() throws Exception {
        var realm = TrustedRealmBO.builder().issuer(ISSUER).build();
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(realm);
        when(audits.save(eq(realm), any(), eq(0L))).thenThrow(new org.springframework.dao.DataAccessResourceFailureException("unavailable"));
        assertEquals(DeliveryResult.Kind.RETRYABLE_FAILURE, handler.deliver(context(event())).kind());
    }

    @Test void unconfirmedRepositoryReturnCannotAcknowledgeOutbox() throws Exception {
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(TrustedRealmBO.builder().issuer(ISSUER).build());
        assertEquals(DeliveryResult.Kind.RETRYABLE_FAILURE, handler.deliver(context(event())).kind());
    }

    private Map<String, Object> event() {
        return new LinkedHashMap<>(Map.of("eventId", "event-1", "schemaVersion", 1, "issuer", ISSUER.toASCIIString(),
                "resource", "https://api.example/orders", "clientRef", "a".repeat(64), "result", "SUCCESS",
                "reasonCode", "CLIENT_CREDENTIALS_TOKEN_ISSUED", "occurredAt", NOW.toString()));
    }
    private DeliveryContext context(Map<String, Object> event) throws Exception {
        return new DeliveryContext("event-1", OAuthAuditOutboxDeliveryHandler.CHANNEL, OAuthAuditOutboxDeliveryHandler.DESTINATION,
                mapper.writeValueAsString(event), "application/json", "1", Map.of(), null, 1, 5, NOW);
    }
}
