package top.egon.cola.platform.tianquan.shoubing.contract.state;

import java.net.URI;
import java.time.Instant;

/** Cryptographic context for refresh coordination only; never a business Authentication. */
public record RefreshContextProof(URI issuer, String tenantId, String subject, String clientId,
        String authorizationId, String authenticationJti, String refreshGeneration,
        Instant authorizationExpiresAt, Instant authenticationExpiresAt,
        Instant accessIssuedAt, Instant accessExpiresAt) { }
