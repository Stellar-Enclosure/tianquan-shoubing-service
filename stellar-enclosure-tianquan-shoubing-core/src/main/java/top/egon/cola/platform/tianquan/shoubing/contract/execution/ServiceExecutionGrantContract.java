package top.egon.cola.platform.tianquan.shoubing.contract.execution;

import java.net.URI;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** Internal SERVICE execution-intent exchange; bearer tokens and sealed tickets are never diagnostic data. */
public final class ServiceExecutionGrantContract {
    public static final String ISSUE_PATH = "/internal/v1/identity/service-execution-grants:issue";
    public static final String RESOLVE_PATH = "/internal/v1/identity/service-execution-grants:resolve";
    public static final String REVOKE_PATH = "/internal/v1/identity/service-execution-grants:revoke";

    private ServiceExecutionGrantContract() { }

    public record Ticket(String grantId, String ciphertext) {
        public Ticket {
            if (grantId == null || !grantId.matches("8[0-9]{62}") || ciphertext == null
                    || !ciphertext.startsWith("ENC:v1:") || ciphertext.length() > 32_768) throw invalid();
        }
        @Override public String toString() { return "ServiceExecutionGrantTicket[redacted]"; }
    }

    public record IssueRequest(String serviceToken, String purpose, String intentId, String bindingSha256,
                               boolean sessionRequired, Instant deadlineAt) {
        public IssueRequest {
            if (serviceToken == null || serviceToken.length() > 16_384 || !serviceToken.matches("[A-Za-z0-9._~+/-]+=*")
                    || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || bindingSha256 == null
                    || !bindingSha256.matches("[0-9a-f]{64}") || deadlineAt == null) throw invalid();
            uuid(intentId);
        }
        @Override public String toString() { return "ServiceExecutionGrantIssueRequest[redacted]"; }
    }

    public record ResolveRequest(Ticket ticket) {
        public ResolveRequest { if (ticket == null) throw invalid(); }
        @Override public String toString() { return "ServiceExecutionGrantResolveRequest[redacted]"; }
    }

    public record RevokeRequest(Ticket ticket) {
        public RevokeRequest { if (ticket == null) throw invalid(); }
        @Override public String toString() { return "ServiceExecutionGrantRevokeRequest[redacted]"; }
    }

    public record Issued(Ticket ticket, Instant expiresAt) {
        public Issued { if (ticket == null || expiresAt == null) throw invalid(); }
        @Override public String toString() { return "ServiceExecutionGrantIssued[redacted]"; }
    }

    /** An attested service tuple, including its owner-registered source resource. */
    public record Source(String clientId, String appId, String businessCode, String applicationCode,
                         String environment, String resourceUri) {
        public Source {
            if (!text(clientId) || !text(appId) || !text(businessCode) || !text(applicationCode) || !text(environment)) throw invalid();
            secureUri(resourceUri);
        }
        @Override public String toString() { return "ServiceExecutionGrantSource[redacted]"; }
    }

    public record Resolution(String grantId, String issuer, long tenantId, String subject, String resource,
            Source source, Source subjectSource, String purpose, String intentId, String bindingSha256,
            boolean sessionRequired, Instant expiresAt, Instant intentDeadlineAt, Set<String> scopes) {
        public Resolution {
            if (grantId == null || !grantId.matches("8[0-9]{62}") || tenantId <= 0 || !text(subject)
                    || source == null || subjectSource == null || !subject.equals(subjectSource.clientId())
                    || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}")
                    || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}")
                    || expiresAt == null || intentDeadlineAt == null || expiresAt.isAfter(intentDeadlineAt)
                    || scopes == null || scopes.isEmpty() || scopes.size() > 64
                    || scopes.stream().anyMatch(scope -> scope == null || !scope.matches("[A-Za-z0-9:._-]{1,128}"))) throw invalid();
            secureUri(issuer); secureUri(resource); uuid(intentId);
            if (!source.resourceUri().equals(resource)) throw invalid();
            scopes = Set.copyOf(scopes);
        }
        @Override public String toString() { return "ServiceExecutionGrantResolution[redacted]"; }
    }

    private static boolean text(String value) {
        return value != null && !value.isBlank() && value.length() <= 128 && value.equals(value.trim())
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static void uuid(String value) {
        try { if (value == null || value.length() != 36 || !UUID.fromString(value).toString().equals(value)) throw invalid(); }
        catch (IllegalArgumentException malformed) { throw invalid(); }
    }

    private static void secureUri(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.normalize().equals(uri)
                    || value.length() > 2048) throw invalid();
        } catch (RuntimeException malformed) { throw invalid(); }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SERVICE_EXECUTION_GRANT_REQUEST_INVALID"); }
}
