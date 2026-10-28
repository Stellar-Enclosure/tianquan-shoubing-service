package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.springframework.stereotype.Component;

/** Refuses a partially provisioned stateless authority before a host can serve requests. */
@Component("oauthStateSchemaValidator")
public class OAuthStateSchemaValidator {

    private static final Map<String, Set<String>> REQUIRED_COLUMNS = Map.ofEntries(
            Map.entry("oauth_client", Set.of("browser_bound", "post_logout_redirect_uris")),
            Map.entry("oauth_authorization", Set.of("requested_scopes", "resource_uri", "authentication_jti_digest",
                    "client_browser_binding_digest", "interaction_id", "refresh_generation", "retain_until")),
            Map.entry("oauth_token", Set.of("authorization_pk", "token_digest", "refresh_generation", "consumed_at", "retain_until")),
            Map.entry("oauth_consent", Set.of("resource_uri")),
            Map.entry("oauth_revocation", Set.of("retain_until")),
            Map.entry("oauth_security_state", Set.of("directory_subject_revision", "directory_subject_fingerprint", "directory_subject_ordered_revision")),
            Map.entry("oauth_subject_tenant_history", Set.of("tenant_id", "identity_sub", "identity_tenant_id", "deleted_at")),
            Map.entry("oauth_subject_revocation_task", Set.of("identity_sub", "target_tenant_id", "source_revision",
                    "subject_enabled", "status", "next_attempt_at", "lease_owner", "lease_until")),
            Map.entry("oauth_password_change_receipt", Set.of("tenant_id", "operation_key", "identity_sub", "origin_tenant_id")),
            Map.entry("oauth_subject_delivery_receipt", Set.of("tenant_id", "event_id", "identity_sub", "source_revision", "previous_revision", "payload_fingerprint")),
            Map.entry("oauth_resource_fence", Set.of("id", "tenant_id", "version", "deleted_at")),
            Map.entry("oauth_audit", Set.of("event_fingerprint", "source_client_pk", "source_issuer", "retain_until")),
            Map.entry("oauth_authentication", Set.of("jti_digest", "browser_binding_digest", "subject_generation",
                    "realm_generation", "authenticated_at", "expires_at", "retain_until", "revoked_at")),
            Map.entry("oauth_interaction", Set.of("interaction_id", "purpose", "request_ciphertext", "csrf_digest",
                    "browser_binding_digest", "client_browser_binding_digest", "authentication_jti_digest",
                    "state", "expires_at", "retain_until", "consumed_at")),
            Map.entry("oauth_audit_inbox", Set.of("event_id", "event_fingerprint", "source_issuer", "source_client_pk",
                    "state", "claim_token", "claim_generation", "lease_until", "processing_deadline", "retain_until")),
            Map.entry("oauth_audit_receipt", Set.of("receipt_id", "event_fingerprint", "inbox_pk", "audit_pk", "outcome", "retain_until")),
            Map.entry("oauth_audit_dead_letter", Set.of("inbox_pk", "event_fingerprint", "failure_code", "terminal_at", "retain_until")));

    private static final Set<String> REQUIRED_CONSTRAINTS = Set.of(
            "pk_oauth_subject_tenant_history", "uk_oauth_subject_task", "ck_oauth_subject_task_lease", "ck_oauth_subject_source_fingerprint",
            "uk_oauth_password_receipt_operation",
            "ck_oauth_subject_ordered_revision", "ck_oauth_subject_delivery_fingerprint", "uk_oauth_subject_delivery_event", "uk_oauth_subject_delivery_revision",
            "uk_oauth_resource_fence_partition", "ck_oauth_resource_fence_scope",
            "uk_oauth_authentication_jti", "uk_oauth_interaction_identity",
            "fk_oauth_authorization_authentication", "fk_oauth_authorization_interaction",
            "fk_oauth_token_authorization", "ck_oauth_authorization_scope_ceiling",
            "ck_oauth_token_generation", "uk_oauth_audit_inbox_identity",
            "uk_oauth_audit_receipt_event", "fk_oauth_audit_receipt_inbox",
            "fk_oauth_audit_receipt_audit", "ck_oauth_audit_inbox_claim");
    private static final Set<String> REQUIRED_TRIGGERS = Set.of(
            "oauth_grant.tr_oauth_grant_client_fence", "oauth_identity_membership.tr_oauth_subject_membership_fence",
            "oauth_resource.tr_oauth_resource_fence");

    public void validate(DataSource dataSource) {
        Map<String, Set<String>> columns = new HashMap<>();
        Set<String> constraints = new HashSet<>();
        Set<String> triggers = new HashSet<>();
        try (Connection connection = dataSource.getConnection()) {
            try (var rows = connection.getMetaData().getColumns(null, "tianquan_oauth", "%", "%")) {
                while (rows.next()) {
                    columns.computeIfAbsent(rows.getString("TABLE_NAME"), ignored -> new HashSet<>())
                            .add(rows.getString("COLUMN_NAME"));
                }
            }
            try (var statement = connection.prepareStatement("""
                    select c.conname from pg_constraint c
                    join pg_namespace n on n.oid = c.connamespace
                    where n.nspname = ?
                    """)) {
                statement.setString(1, "tianquan_oauth");
                try (var rows = statement.executeQuery()) {
                    while (rows.next()) { constraints.add(rows.getString(1)); }
                }
            }
            try (var statement = connection.prepareStatement("""
                    select c.relname, t.tgname from pg_trigger t
                    join pg_class c on c.oid = t.tgrelid
                    join pg_namespace n on n.oid = c.relnamespace
                    where n.nspname = ? and not t.tgisinternal and t.tgenabled in ('O', 'A')
                    """)) {
                statement.setString(1, "tianquan_oauth");
                try (var rows = statement.executeQuery()) {
                    while (rows.next()) { triggers.add(rows.getString(1) + "." + rows.getString(2)); }
                }
            }
        } catch (SQLException unavailable) {
            throw new IllegalStateException("OAUTH_STATE_SCHEMA_UNAVAILABLE", unavailable);
        }
        requireShape(columns, constraints, triggers);
    }

    static void requireShape(Map<String, Set<String>> columns, Set<String> constraints, Set<String> triggers) {
        REQUIRED_COLUMNS.forEach((table, required) -> {
            if (!columns.getOrDefault(table, Set.of()).containsAll(required)) {
                throw new IllegalStateException("OAUTH_STATE_SCHEMA_INCOMPLETE:" + table);
            }
        });
        if (!constraints.containsAll(REQUIRED_CONSTRAINTS)
                || !triggers.containsAll(REQUIRED_TRIGGERS)
                || columns.getOrDefault("oauth_revocation", Set.of()).contains("projection_status")) {
            throw new IllegalStateException("OAUTH_STATE_SCHEMA_CONSTRAINTS_INVALID");
        }
    }
}
