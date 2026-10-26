package top.egon.cola.platform.tianquan.shoubing.starter.state;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.*;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import reactor.core.scheduler.Schedulers;
import top.egon.cola.platform.tianquan.shoubing.contract.state.*;

class ReactiveIdentityStateAdapterTest {
    @Test void bothBlockingOperationsRunOnTheExplicitBoundedWorkerAndRemainCold() {
        var delegate = mock(IdentityAuthorityClient.class); var thread = new AtomicReference<String>();
        var response = IdentitySecurityStateResponse.denied(IdentityStatePurpose.ACCESS_VALIDATION, "TOKEN_REVOKED");
        when(delegate.resolve(any())).thenAnswer(call -> { thread.set(Thread.currentThread().getName()); return response; });
        when(delegate.appendAudit(any())).thenAnswer(call -> { thread.set(Thread.currentThread().getName()); return receipt(call.getArgument(0)); });
        var scheduler = Schedulers.newBoundedElastic(2, 8, "controlled-identity-authority");
        try {
            var adapter = new ReactiveIdentityAuthorityClient(delegate, scheduler);
            var pending = adapter.resolve(IdentitySecurityStateRequest.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION).build());
            verifyNoInteractions(delegate); assertThat(pending.block(Duration.ofSeconds(2))).isSameAs(response);
            assertThat(thread.get()).startsWith("controlled-identity-authority-");
            assertThat(adapter.appendAudit(event()).block(Duration.ofSeconds(2)).eventId()).isEqualTo(event().eventId());
            assertThat(thread.get()).startsWith("controlled-identity-authority-");
            doReturn(null).when(delegate).resolve(any());
            assertThatThrownBy(() -> pending.block(Duration.ofSeconds(2))).hasMessage("IDENTITY_AUTHORITY_RESPONSE_INVALID");
            when(delegate.resolve(any())).thenThrow(new IllegalStateException("controlled SQL timeout"));
            assertThatThrownBy(() -> pending.block(Duration.ofSeconds(2))).hasMessage("controlled SQL timeout");
        } finally { scheduler.dispose(); }
    }
}
