package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.springframework.dao.OptimisticLockingFailureException;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthRevocationMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSecurityStateMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.converter.OAuthRevocationConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.converter.OAuthSecurityStateConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthRevocationPO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthSecurityStatePO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.OAuthRevocationRepositoryImpl;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.OAuthSecurityStateRepositoryImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthSecurityReplicaWriteTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private static final TrustedRealmBO REALM = TrustedRealmBO.builder()
            .issuer(URI.create("https://auth.example/tenants/1001")).realmKey("tenant:1001")
            .realmType(RealmTypeEnum.TENANT).storagePartitionId(1001L).businessTenantId(1001L).trustVersion(0L).build();

    @Test
    void mappedCandidatesAreUnlockedAndWritesMatchTenantIdentityAndVersion() throws Exception {
        var configuration = new org.apache.ibatis.session.Configuration();
        for (String name : List.of("OAuthSecurityStateMapper", "OAuthRevocationMapper")) {
            String path = "mapper/token/" + name + ".xml";
            try (var input = getClass().getClassLoader().getResourceAsStream(path)) {
                new org.apache.ibatis.builder.xml.XMLMapperBuilder(input, configuration, path, configuration.getSqlFragments()).parse();
            }
            String prefix = "top.egon.cola.platform.tianquan.shoubing.admin.token.dao." + name + ".";
            var parameters = java.util.Map.of("tenantId", 1001L, "targetType", OAuthSecurityTargetEnum.JTI,
                    "targetKey", "12345", "po", name.equals("OAuthRevocationMapper")
                            ? new OAuthRevocationPO() : new OAuthSecurityStatePO(), "expectedVersion", 1L);
            String read = configuration.getMappedStatement(prefix + "selectByTarget").getBoundSql(parameters).getSql()
                    .toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
            String write = configuration.getMappedStatement(prefix + "updateExpectedVersion").getBoundSql(parameters).getSql()
                    .toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
            assertThat(read).contains("tenant_id = ?", "target_type = ?", "target_key = ?")
                    .doesNotContain("for update", "for share");
            assertThat(write).contains("tenant_id = ?", "id = ?", "target_type = ?", "target_key = ?",
                    "version = ?", "deleted_at is null");
        }
    }

    @Test
    void concurrentGenerationChangesFromTheSameReplicaVersionHaveOneWinner() throws Exception {
        var mapper = mock(OAuthSecurityStateMapper.class);
        var row = new OAuthSecurityStatePO();
        row.setId(21L); row.setTenantId(1001L); row.setVersion(1L); row.setTargetType(OAuthSecurityTargetEnum.SUBJECT);
        row.setTargetKey("user"); row.setGeneration(1L); row.setRevision(1L); row.setEnabled(true); row.setReasonCode("INITIALIZED");
        row.setDirectorySubjectRevision(0L); row.setDirectorySubjectOrderedRevision(0L);
        var value = OAuthSecurityStateBO.builder().id(21L).version(2L).targetType(OAuthSecurityTargetEnum.SUBJECT)
                .targetKey("user").generation(2L).revision(2L).enabled(false).reasonCode("REVOKED").build();
        var barrier = new CyclicBarrier(2); var won = new AtomicBoolean();
        when(mapper.selectByTarget(eq(1001L), eq(OAuthSecurityTargetEnum.SUBJECT), eq("user")))
                .thenAnswer(call -> { barrier.await(5, TimeUnit.SECONDS); return row; });
        when(mapper.updateExpectedVersion(eq(1001L), any(), eq(1L))).thenAnswer(call -> won.compareAndSet(false, true) ? 1 : 0);
        var repository = new OAuthSecurityStateRepositoryImpl(mapper, new EgonColaMybatisPlusProperties(),
                Mappers.getMapper(OAuthSecurityStateConverter.class), () -> "service:tianquan-shoubing", Clock.fixed(NOW, ZoneOffset.UTC));

        assertOneWinner(() -> { repository.save(REALM, value, 1L); return true; });
        verify(mapper, never()).selectByTargetForUpdate(anyLong(), any(), anyString());
    }

    @Test
    void concurrentRevocationExtensionsFromTheSameReplicaVersionHaveOneWinner() throws Exception {
        var mapper = mock(OAuthRevocationMapper.class);
        var row = new OAuthRevocationPO();
        row.setId(22L); row.setTenantId(1001L); row.setVersion(1L); row.setTargetType(OAuthSecurityTargetEnum.JTI);
        row.setTargetKey("12345"); row.setReasonCode("REVOKED"); row.setRevokedAt(NOW);
        row.setExpiresAt(NOW.plusSeconds(60)); row.setRevision(1L); row.setRetainUntil(NOW.plusSeconds(86460));
        var value = OAuthRevocationBO.builder().id(22L).version(2L).targetType(OAuthSecurityTargetEnum.JTI)
                .targetKey("12345").reasonCode("REVOKED").revokedAt(NOW).expiresAt(NOW.plusSeconds(120))
                .revision(2L).retainUntil(NOW.plusSeconds(86520)).build();
        var barrier = new CyclicBarrier(2); var won = new AtomicBoolean();
        when(mapper.selectByTarget(eq(1001L), eq(OAuthSecurityTargetEnum.JTI), eq("12345")))
                .thenAnswer(call -> { barrier.await(5, TimeUnit.SECONDS); return row; });
        when(mapper.updateExpectedVersion(eq(1001L), any(), eq(1L))).thenAnswer(call -> won.compareAndSet(false, true) ? 1 : 0);
        var repository = new OAuthRevocationRepositoryImpl(mapper, new EgonColaMybatisPlusProperties(),
                Mappers.getMapper(OAuthRevocationConverter.class), () -> "service:tianquan-shoubing", Clock.fixed(NOW, ZoneOffset.UTC));

        assertOneWinner(() -> { repository.save(REALM, value, 1L); return true; });
        verify(mapper, never()).selectByTargetForUpdate(anyLong(), any(), anyString());
    }

    private static void assertOneWinner(Callable<Boolean> action) throws Exception {
        try (var workers = Executors.newFixedThreadPool(2)) {
            Callable<Boolean> guarded = () -> {
                try { return action.call(); }
                catch (OptimisticLockingFailureException conflict) { return false; }
            };
            var first = workers.submit(guarded); var second = workers.submit(guarded);
            assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
    }
}
