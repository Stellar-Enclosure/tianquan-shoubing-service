package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthScheduledRealmCatalog;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthSecurityProjectionComponentTest {
    private static final Instant NOW = Instant.parse("2026-10-23T00:00:00Z");
    private static final TrustedRealmBO REALM = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L).businessTenantId(101L).trustVersion(2L).build();
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthScheduledRealmCatalog scheduledRealms = mock(OAuthScheduledRealmCatalog.class);
    private final org.springframework.transaction.PlatformTransactionManager transactions = mock(org.springframework.transaction.PlatformTransactionManager.class);
    private final Map<String, OAuthSecurityStateBO> rows = new HashMap<>();
    private OAuthSecurityProjectionComponent component;

    @BeforeEach void setUp() {
        component = new OAuthSecurityProjectionComponent(states, revocations, authorizations, clients, realms, scheduledRealms,
                Clock.fixed(NOW, ZoneOffset.UTC), transactions);
        var row = OAuthRealmBO.builder().issuer(REALM.getIssuer()).realmKey(REALM.getRealmKey()).status("ACTIVE").activeKid("key").build();
        when(realms.findByRealmKey(REALM)).thenReturn(Optional.of(row));
        when(realms.fenceRecovery(eq(REALM), any(), anyList(), anyBoolean())).thenReturn(true);
        when(realms.fenceActiveObservedVersion(REALM)).thenReturn(true);
        when(realms.findByIssuer(REALM)).thenReturn(Optional.of(row));
        when(clients.findAllByRealm(REALM)).thenReturn(List.of(OAuthClientBO.builder().id(501L).clientId("client").status(OAuthClient.Status.ACTIVE).build()));
        when(states.findByTarget(eq(REALM), any(), anyString())).thenAnswer(call -> Optional.ofNullable(rows.get(call.getArgument(1) + ":" + call.getArgument(2))));
        when(states.save(eq(REALM), any(), eq(0L))).thenAnswer(call -> {
            OAuthSecurityStateBO value = call.getArgument(1); rows.put(value.getTargetType() + ":" + value.getTargetKey(), value); return value;
        });
        when(states.findSnapshot(eq(REALM), eq(501L), any())).thenAnswer(call -> rows.values().stream()
                .filter(value -> value.getTargetType() != OAuthSecurityTargetEnum.SUBJECT || value.getTargetKey().equals(call.getArgument(2))).toList());
        put(OAuthSecurityTargetEnum.REALM, "self", 1, 4); put(OAuthSecurityTargetEnum.CLIENT, "501", 2, 5); put(OAuthSecurityTargetEnum.SUBJECT, "alice", 3, 6);
    }

    @Test void snapshotUsesCommittedGenerationsWithoutRedisReadiness() {
        var snapshot = component.snapshotForAuthorization(REALM, 501L, "USER", "alice");
        assertEquals(1L, snapshot.getRealmGeneration()); assertEquals(2L, snapshot.getClientGeneration());
        assertEquals(3L, snapshot.getSubjectGeneration()); assertEquals(6L, snapshot.getRevision());
        assertEquals("postgresql:2", snapshot.getReadyEpoch());
        verify(realms).fenceActiveObservedVersion(REALM);
        verify(realms, never()).findByRealmKeyForUpdate(any());
    }

    @Test void alreadyFencedRealmDoesNotRepeatTheLockingRead() {
        var snapshot = component.snapshotForFencedRealm(REALM, 501L, "USER", "alice");
        assertEquals(1L, snapshot.getRealmGeneration());
        assertEquals(2L, snapshot.getClientGeneration());
        assertEquals(3L, snapshot.getSubjectGeneration());
        verify(realms, never()).findByRealmKeyForUpdate(any());
    }

    @Test void currentSnapshotReadsOneRepositorySnapshotAndRejectsRevocation() {
        var expected = component.snapshotForAuthorization(REALM, 501L, "USER", "alice");
        assertDoesNotThrow(() -> component.requireCurrentSnapshot(REALM, 501L, "USER", "alice", expected));
        put(OAuthSecurityTargetEnum.SUBJECT, "alice", 4, 7);
        assertThrows(OAuth2AuthenticationException.class, () -> component.requireCurrentSnapshot(REALM, 501L, "USER", "alice", expected));
        verify(states, times(2)).findSnapshot(REALM, 501L, "alice");
    }

    @Test void disabledStateFailsClosed() {
        rows.get("SUBJECT:alice").setEnabled(false);
        assertThrows(OAuth2AuthenticationException.class, () -> component.snapshotForAuthorization(REALM, 501L, "USER", "alice"));
        rows.get("REALM:self").setEnabled(false); assertFalse(component.isIssuerReady(REALM));
    }

    @Test void missingStateCannotResetGenerationWhenHistoryExists() {
        rows.clear();
        when(authorizations.findExpiredBefore(eq(REALM), any(), eq(0L), eq(1))).thenReturn(List.of(OAuthAuthorizationBO.builder().id(1L).build()));
        assertThrows(OAuth2AuthenticationException.class, () -> component.recover(REALM));
        verify(states, never()).save(any(), any(), anyLong());
    }

    @Test void replicaMissCannotInitializeSubjectWithoutPrimaryAbsenceConfirmation() {
        rows.remove("SUBJECT:alice");
        rows.get("REALM:self").setId(11L).setVersion(2L);
        when(states.fenceRealmIfSubjectAbsent(REALM, 11L, 2L, "alice", NOW)).thenReturn(false);
        assertThrows(org.springframework.dao.OptimisticLockingFailureException.class,
                () -> component.snapshotForAuthorization(REALM, 501L, "USER", "alice"));
        verify(states, never()).save(any(), any(), anyLong());
        verify(realms, never()).findByRealmKeyForUpdate(any());
    }

    @Test void emptyAuthorityBootstrapIsIdempotent() {
        rows.clear(); assertEquals(0, component.recover(REALM)); assertEquals(2, rows.size());
        assertEquals(0, component.recover(REALM)); verify(states, times(2)).save(eq(REALM), any(), eq(0L));
        verify(realms, never()).findByRealmKeyForUpdate(any());
    }

    @Test void recoveryUsesTheCommittedWriteResultWhileTheReplicaStillMissesIt() {
        rows.clear();
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self")).thenReturn(Optional.empty());
        assertEquals(0L, component.recover(REALM));
        verify(states, times(1)).findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self");
        verify(states).save(eq(REALM), argThat(value -> value.getTargetType() == OAuthSecurityTargetEnum.REALM), eq(0L));
    }

    @Test void scheduledRecoveryUsesIndependentTransactionsAndContinuesAfterARealmFailure() {
        var first = scheduledRealm(101L); var second = scheduledRealm(102L);
        when(scheduledRealms.findAll()).thenReturn(List.of(first, second));
        when(transactions.getTransaction(any())).thenAnswer(call -> new org.springframework.transaction.support.SimpleTransactionStatus());
        var worker = spy(component);
        doThrow(new IllegalStateException("first realm unavailable")).when(worker).recover(argThat(realm -> realm.getStoragePartitionId() == 101L));
        doReturn(0L).when(worker).recover(argThat(realm -> realm.getStoragePartitionId() == 102L));

        assertThrows(IllegalStateException.class, worker::recoverRegisteredRealms);

        verify(worker).recover(argThat(realm -> realm.getStoragePartitionId() == 101L));
        verify(worker).recover(argThat(realm -> realm.getStoragePartitionId() == 102L));
        verify(transactions, times(2)).getTransaction(any());
        verify(transactions).rollback(any()); verify(transactions).commit(any());
    }

    @Test void recoveryRollsBackOnePrimaryWithoutUndoingAnotherPrimary() {
        var first = new org.h2.jdbcx.JdbcDataSource();
        var second = new org.h2.jdbcx.JdbcDataSource();
        first.setURL("jdbc:h2:mem:" + java.util.UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        second.setURL("jdbc:h2:mem:" + java.util.UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var firstJdbc = new org.springframework.jdbc.core.JdbcTemplate(first);
        var secondJdbc = new org.springframework.jdbc.core.JdbcTemplate(second);
        firstJdbc.execute("CREATE TABLE recovered (id BIGINT)"); secondJdbc.execute("CREATE TABLE recovered (id BIGINT)");
        var router = new org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource() {
            @Override protected Object determineCurrentLookupKey() { return org.slf4j.MDC.get("tenantId"); }
        };
        router.setTargetDataSources(Map.of("101", first, "102", second));
        router.setDefaultTargetDataSource(first); router.afterPropertiesSet();
        var source = new org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy(router);
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(source);
        var manager = new org.springframework.jdbc.datasource.DataSourceTransactionManager(source);
        var worker = spy(new OAuthSecurityProjectionComponent(states, revocations, authorizations, clients, realms,
                scheduledRealms, Clock.fixed(NOW, ZoneOffset.UTC), manager));
        when(scheduledRealms.findAll()).thenReturn(List.of(scheduledRealm(101L), scheduledRealm(102L)));
        doAnswer(call -> {
            TrustedRealmBO realm = call.getArgument(0);
            org.slf4j.MDC.put("tenantId", realm.getStoragePartitionId().toString());
            try {
                jdbc.update("INSERT INTO recovered VALUES (?)", realm.getStoragePartitionId());
                if (realm.getStoragePartitionId() == 101L) throw new IllegalStateException("first realm unavailable");
                return 0L;
            } finally { org.slf4j.MDC.remove("tenantId"); }
        }).when(worker).recover(any());

        assertThrows(IllegalStateException.class, worker::recoverRegisteredRealms);
        assertEquals(0, firstJdbc.queryForObject("SELECT count(*) FROM recovered", Integer.class));
        assertEquals(1, secondJdbc.queryForObject("SELECT count(*) FROM recovered", Integer.class));
    }

    private static OAuthRealmBO scheduledRealm(long id) {
        return OAuthRealmBO.builder().issuer(URI.create("https://idp.example/tenants/" + id))
                .realmKey("tenant:" + id).realmType(RealmTypeEnum.TENANT).storagePartitionId(id)
                .businessTenantId(id).trustVersion(0L).status("ACTIVE").build();
    }

    @Test void incompleteReplicaCannotInitializeGenerations() {
        rows.clear();
        when(realms.fenceRecovery(eq(REALM), any(), anyList(), eq(true))).thenReturn(false);
        assertThrows(OAuth2AuthenticationException.class, () -> component.recover(REALM));
        verify(states, never()).save(any(), any(), anyLong());
        verify(realms, never()).findByRealmKeyForUpdate(any());
    }

    @Test void outboxAcknowledgementCannotInventARevisionOrChangeAuthority() {
        var event = new OAuthSecurityChangedEvent("event", 1, REALM.getIssuer(), REALM.getRealmKey(), 4,
                "REALM", "self", 1L, null, "CHANGED", NOW, null);
        component.applyProjection(REALM, event);
        assertThrows(OAuth2AuthenticationException.class, () -> component.applyProjection(REALM,
                new OAuthSecurityChangedEvent("event2", 1, REALM.getIssuer(), REALM.getRealmKey(), 99,
                        "REALM", "self", 1L, null, "CHANGED", NOW, null)));
        verify(states, never()).save(any(), any(), anyLong());
    }

    private void put(OAuthSecurityTargetEnum target, String key, long generation, long revision) {
        rows.put(target + ":" + key, OAuthSecurityStateBO.builder().targetType(target).targetKey(key)
                .generation(generation).revision(revision).enabled(true).reasonCode("INITIALIZED").build());
    }
}
