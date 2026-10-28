package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller;

import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.mock.web.MockHttpServletRequest;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthBrowserInteractionComponent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthPasswordChangeControllerTest {
    @Test void transientReplicaDelayReturnsRetryableResponseAndClearsPasswords() {
        var interactions = mock(OAuthBrowserInteractionComponent.class);
        var old = new AtomicReference<char[]>(); var next = new AtomicReference<char[]>();
        when(interactions.changeRequiredPassword(any(), any(char[].class), any(char[].class))).thenAnswer(invocation -> {
            old.set(invocation.getArgument(1)); next.set(invocation.getArgument(2));
            throw new TransientDataAccessResourceException("replica behind");
        });
        var request = new MockHttpServletRequest();
        request.addParameter("old_password", "old-secret"); request.addParameter("new_password", "new-secret"); request.addParameter("_csrf", "csrf");
        var response = new OAuthPasswordChangeController(interactions).change(request);
        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("1");
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(old.get()).containsOnly('\0'); assertThat(next.get()).containsOnly('\0');
    }
}
