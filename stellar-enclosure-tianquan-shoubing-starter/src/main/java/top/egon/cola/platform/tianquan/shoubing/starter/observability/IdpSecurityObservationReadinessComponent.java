package top.egon.cola.platform.tianquan.shoubing.starter.observability;

import java.util.Objects;
import java.util.function.BooleanSupplier;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;

/** Validates finite authority routing only; each protected request proves durability with its own SQL receipt. */
public final class IdpSecurityObservationReadinessComponent {
    private final IdentityAuthorityClientResolver authority;
    private final TrustedIssuerRegistry issuers;
    private final OAuthUsageObservationProperties usage;

    public IdpSecurityObservationReadinessComponent(IdentityAuthorityClientResolver authority,
            TrustedIssuerRegistry issuers, OAuthUsageObservationProperties usage) {
        this.authority = Objects.requireNonNull(authority, "authority");
        this.issuers = Objects.requireNonNull(issuers, "issuers");
        this.usage = Objects.requireNonNull(usage, "usage");
    }

    public BooleanSupplier readiness() {
        return () -> {
            try {
                if (!usage.isEnabled() || usage.getFallbackIssuer() == null || issuers.activeIssuers().isEmpty()
                        || issuers.findByIssuer(usage.getFallbackIssuer().toASCIIString()).isEmpty()) { return false; }
                for (var issuer : issuers.activeIssuers()) {
                    if (authority.forIssuer(issuer.issuer()) == null) { return false; }
                }
                return true;
            } catch (RuntimeException unavailable) { return false; }
        };
    }
}
