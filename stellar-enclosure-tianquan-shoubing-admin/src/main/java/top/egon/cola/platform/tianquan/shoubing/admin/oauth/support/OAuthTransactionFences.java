package top.egon.cola.platform.tianquan.shoubing.admin.oauth.support;

import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

/** Reuses successful primary fences only within the transaction that acquired them. */
public final class OAuthTransactionFences {
    private OAuthTransactionFences() { }

    public static boolean realm(OAuthRealmRepository repository, TrustedRealmBO realm) {
        State state = state();
        RealmKey key = RealmKey.of(realm);
        if (state != null && state.realms.containsKey(key)) return true;
        if (!repository.fenceObservedVersion(realm)) return false;
        if (state != null) state.realms.put(key, Boolean.FALSE);
        return true;
    }

    public static boolean activeRealm(OAuthRealmRepository repository, TrustedRealmBO realm) {
        State state = state();
        RealmKey key = RealmKey.of(realm);
        if (state != null && Boolean.TRUE.equals(state.realms.get(key))) return true;
        if (!repository.fenceActiveObservedVersion(realm)) return false;
        if (state != null) state.realms.put(key, Boolean.TRUE);
        return true;
    }

    public static boolean client(OAuthClientRepository repository, TrustedRealmBO realm, OAuthClientBO client) {
        Objects.requireNonNull(client, "client");
        State state = state();
        ClientKey key = new ClientKey(RealmKey.of(realm), client.getId());
        ClientFence current = state == null ? null : state.clients.get(key);
        if (current != null) {
            return current.observedVersion() == client.getVersion()
                    && Objects.equals(current.clientId(), client.getClientId());
        }
        if (!repository.fenceObservedVersion(realm, client)) return false;
        if (state != null) state.clients.put(key, new ClientFence(client.getClientId(), client.getVersion(),
                Math.addExact(client.getVersion(), 1L)));
        return true;
    }

    public static boolean grant(OAuthClientRepository repository, TrustedRealmBO realm,
            OAuthClientBO client, OAuthGrantBO grant) {
        State state = state();
        if (state == null) throw new IllegalStateException("OAUTH_TRANSACTION_FENCE_REQUIRED");
        ClientKey key = new ClientKey(RealmKey.of(realm), client.getId());
        ClientFence current = state.clients.get(key);
        if (current == null || current.observedVersion() != client.getVersion()
                || !Objects.equals(current.clientId(), client.getClientId())) return false;
        if (!repository.fenceGrantObservedVersion(realm, client, current.currentVersion(), grant)) return false;
        state.clients.put(key, new ClientFence(current.clientId(), current.observedVersion(),
                Math.addExact(current.currentVersion(), 1L)));
        return true;
    }

    public static void clientWritten(TrustedRealmBO realm, OAuthClientBO client) {
        State state = state();
        if (state == null) return;
        ClientKey key = new ClientKey(RealmKey.of(realm), client.getId());
        state.clients.put(key, new ClientFence(client.getClientId(), client.getVersion(), client.getVersion()));
        state.writes.put(key, new ClientWrite(client.getClientId(), client.getVersion(), client.getStatus()));
    }

    public static boolean isClientWritten(TrustedRealmBO realm, OAuthClientBO client) {
        State state = state();
        if (state == null || client == null) return false;
        ClientWrite write = state.writes.get(new ClientKey(RealmKey.of(realm), client.getId()));
        return write != null && Objects.equals(write.clientId(), client.getClientId())
                && write.version() == client.getVersion() && write.status() == client.getStatus();
    }

    public static void securityStateWritten(TrustedRealmBO realm, OAuthSecurityStateBO value) {
        State state = state();
        if (state == null) return;
        var key = new SecurityKey(RealmKey.of(realm), value.getTargetType(), value.getTargetKey());
        state.security.put(key, new SecurityValue(value.getId(), value.getVersion(), value.getGeneration(),
                value.isEnabled(), value.getRevision(), value.getDirectorySubjectRevision(),
                value.getDirectorySubjectFingerprint(), value.getReasonCode()));
    }

    public static OAuthSecurityStateBO securityState(TrustedRealmBO realm, OAuthSecurityTargetEnum type, String targetKey) {
        State state = state();
        if (state == null) return null;
        var value = state.security.get(new SecurityKey(RealmKey.of(realm), type, targetKey));
        return value == null ? null : OAuthSecurityStateBO.builder().id(value.id()).version(value.version())
                .targetType(type).targetKey(targetKey).generation(value.generation()).enabled(value.enabled())
                .revision(value.revision()).directorySubjectRevision(value.directorySubjectRevision())
                .directorySubjectFingerprint(value.directorySubjectFingerprint()).reasonCode(value.reasonCode()).build();
    }

    public static void identityUserWritten(long partition, IdentityUser user) {
        State state = state();
        if (state != null) state.identityUsers.put(new IdentityKey(partition, user.id()), user);
    }

    public static IdentityUser identityUser(long partition, String subject) {
        State state = state();
        return state == null ? null : state.identityUsers.get(new IdentityKey(partition, subject));
    }

    private static State state() {
        State current = (State) TransactionSynchronizationManager.getResource(OAuthTransactionFences.class);
        if (current != null) return current;
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()) return null;
        State state = new State();
        TransactionSynchronizationManager.bindResource(OAuthTransactionFences.class, state);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void suspend() { TransactionSynchronizationManager.unbindResource(OAuthTransactionFences.class); }
            @Override public void resume() { TransactionSynchronizationManager.bindResource(OAuthTransactionFences.class, state); }
            @Override public void savepoint(Object point) { state.savepoints.put(point, state.snapshot()); }
            @Override public void savepointRollback(Object point) {
                Snapshot snapshot = state.savepoints.remove(point);
                state.realms.clear(); state.clients.clear(); state.writes.clear(); state.security.clear(); state.identityUsers.clear();
                if (snapshot != null) {
                    state.realms.putAll(snapshot.realms()); state.clients.putAll(snapshot.clients()); state.writes.putAll(snapshot.writes());
                    state.security.putAll(snapshot.security());
                    state.identityUsers.putAll(snapshot.identityUsers());
                }
            }
            @Override public void afterCompletion(int status) {
                TransactionSynchronizationManager.unbindResourceIfPossible(OAuthTransactionFences.class);
            }
        });
        return state;
    }

    private record RealmKey(Long partition, String key, String issuer, Long trustVersion) {
        private static RealmKey of(TrustedRealmBO realm) {
            Objects.requireNonNull(realm, "realm").validateTrustedPartition();
            return new RealmKey(realm.getStoragePartitionId(), realm.getRealmKey(), realm.getIssuer().toASCIIString(), realm.getTrustVersion());
        }
    }
    private record ClientKey(RealmKey realm, Long id) { }
    private record ClientFence(String clientId, long observedVersion, long currentVersion) { }
    private record ClientWrite(String clientId, long version, OAuthClient.Status status) { }
    private record SecurityKey(RealmKey realm, OAuthSecurityTargetEnum type, String key) { }
    private record IdentityKey(long partition, String subject) { }
    private record SecurityValue(Long id, long version, long generation, boolean enabled, long revision,
            long directorySubjectRevision, String directorySubjectFingerprint, String reasonCode) { }
    private record Snapshot(Map<RealmKey, Boolean> realms, Map<ClientKey, ClientFence> clients,
            Map<ClientKey, ClientWrite> writes, Map<SecurityKey, SecurityValue> security,
            Map<IdentityKey, IdentityUser> identityUsers) { }
    private static final class State {
        private final Map<RealmKey, Boolean> realms = new HashMap<>();
        private final Map<ClientKey, ClientFence> clients = new HashMap<>();
        private final Map<ClientKey, ClientWrite> writes = new HashMap<>();
        private final Map<SecurityKey, SecurityValue> security = new HashMap<>();
        private final Map<IdentityKey, IdentityUser> identityUsers = new HashMap<>();
        private final Map<Object, Snapshot> savepoints = new IdentityHashMap<>();
        private Snapshot snapshot() { return new Snapshot(new HashMap<>(realms), new HashMap<>(clients),
                new HashMap<>(writes), new HashMap<>(security), new HashMap<>(identityUsers)); }
    }
}
