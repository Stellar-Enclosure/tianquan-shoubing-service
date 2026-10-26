package top.egon.cola.platform.tianquan.shoubing.starter.state;

import java.net.URI;

/** Selects a fixed SERVICE client using an already verified issuer, never request-supplied destinations. */
@FunctionalInterface
public interface IdentityAuthorityClientResolver {
    IdentityAuthorityClient forIssuer(URI verifiedIssuer);

    /** Local owners retain their exact resource check; remote gateways select an explicit SERVICE binding per target. */
    default IdentityAuthorityClient forResource(URI verifiedIssuer, URI expectedResource) {
        java.util.Objects.requireNonNull(expectedResource, "expectedResource");
        return forIssuer(verifiedIssuer);
    }
}
