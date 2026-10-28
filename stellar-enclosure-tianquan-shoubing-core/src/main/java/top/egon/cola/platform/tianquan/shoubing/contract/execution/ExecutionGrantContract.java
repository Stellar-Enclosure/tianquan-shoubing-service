package top.egon.cola.platform.tianquan.shoubing.contract.execution;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** Internal execution-intent exchange. Tokens and sealed tickets are never diagnostic data. */
public final class ExecutionGrantContract {
    public static final String ISSUE_PATH = "/internal/v1/identity/execution-grants:issue";
    public static final String RESOLVE_PATH = "/internal/v1/identity/execution-grants:resolve";
    public static final String REVOKE_PATH = "/internal/v1/identity/execution-grants:revoke";
    public static final int MAX_REQUEST_BYTES = 64 * 1024;
    public static final int MAX_RESPONSE_BYTES = 64 * 1024;

    private ExecutionGrantContract() { }

    public record Ticket(String grantId, String ciphertext) {
        public Ticket {
            if (grantId == null || !grantId.matches("9[0-9]{62}") || ciphertext == null
                    || !ciphertext.startsWith("ENC:v1:") || ciphertext.length() > 32_768) throw invalid();
        }
        @Override public String toString() { return "ExecutionGrantTicket[redacted]"; }
    }

    public record IssueRequest(String userToken, String purpose, String intentId, String bindingSha256,
                               boolean sessionRequired, Instant deadlineAt) {
        public IssueRequest {
            requireToken(userToken);
            if (purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || bindingSha256 == null
                    || !bindingSha256.matches("[0-9a-f]{64}") || deadlineAt == null) throw invalid();
            try {
                if (intentId == null || intentId.length() != 36 || !UUID.fromString(intentId).toString().equals(intentId)) throw invalid();
            } catch (IllegalArgumentException malformed) { throw invalid(); }
        }
        @Override public String toString() { return "ExecutionGrantIssueRequest[redacted]"; }
    }

    public record ResolveRequest(Ticket ticket) {
        public ResolveRequest { if (ticket == null) throw invalid(); }
        @Override public String toString() { return "ExecutionGrantResolveRequest[redacted]"; }
    }

    public record RevokeRequest(String userToken, Ticket ticket) {
        public RevokeRequest { requireToken(userToken); if (ticket == null) throw invalid(); }
        @Override public String toString() { return "ExecutionGrantRevokeRequest[redacted]"; }
    }

    public record Issued(Ticket ticket, Instant expiresAt) {
        public Issued { if (ticket == null || expiresAt == null) throw invalid(); }
        @Override public String toString() { return "ExecutionGrantIssued[redacted]"; }
    }

    /** Attested source tuple must be compared with the separately authenticated requester. */
    public record Source(String clientId, String appId, String businessCode, String applicationCode, String environment) {
        public Source {
            if (!text(clientId) || !text(appId) || !text(businessCode) || !text(applicationCode) || !text(environment)) throw invalid();
        }
        @Override public String toString() { return "ExecutionGrantSource[redacted]"; }
    }

    public record Resolution(String grantId, String issuer, long tenantId, String subject, String resource, Source source, String purpose,
                             String intentId, String bindingSha256, boolean sessionRequired, Instant expiresAt,
                             Instant intentDeadlineAt, Set<String> scopes) {
        public Resolution {
            if (grantId == null || !grantId.matches("9[0-9]{62}") || issuer == null || issuer.isBlank()
                    || tenantId <= 0 || subject == null || subject.isBlank() || resource == null || resource.isBlank() || source == null
                    || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || intentId == null
                    || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}") || expiresAt == null
                    || intentDeadlineAt == null || scopes == null || scopes.isEmpty() || scopes.size() > 64) throw invalid();
            try { if (!UUID.fromString(intentId).toString().equals(intentId)) throw invalid(); }
            catch (IllegalArgumentException malformed) { throw invalid(); }
            scopes = Set.copyOf(scopes);
            if (scopes.stream().anyMatch(scope -> scope == null || !scope.matches("[A-Za-z0-9:._-]{1,128}"))) throw invalid();
        }
        @Override public String toString() { return "ExecutionGrantResolution[redacted]"; }
    }

    private static void requireToken(String token) {
        if (token == null || token.length() > 16_384 || !token.matches("[A-Za-z0-9._~+/-]+=*")) throw invalid();
    }

    private static boolean text(String value) {
        return value != null && !value.isBlank() && value.length() <= 128 && value.equals(value.trim())
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("EXECUTION_GRANT_REQUEST_INVALID"); }
}
