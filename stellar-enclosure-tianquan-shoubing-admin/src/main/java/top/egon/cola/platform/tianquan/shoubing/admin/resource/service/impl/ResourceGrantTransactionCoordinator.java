package top.egon.cola.platform.tianquan.shoubing.admin.resource.service.impl;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceFenceRepository;

/** Holds platform resource fences while the independent owning-shard transaction commits. */
@Component
@RequiredArgsConstructor
public class ResourceGrantTransactionCoordinator {
    @Qualifier("transactionManager") private final PlatformTransactionManager transactionManager;
    private final OAuthResourceFenceRepository fences;

    public <T> T execute(TrustedRealmBO platform, List<OAuthResourceBO> resources, Supplier<T> action) {
        Objects.requireNonNull(action, "action");
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("OAUTH_RESOURCE_GRANT_AMBIENT_TRANSACTION_UNSUPPORTED");
        }
        if (resources == null || resources.isEmpty() || resources.stream().anyMatch(value -> value == null || value.getId() == null)
                || resources.stream().map(OAuthResourceBO::getId).distinct().count() != resources.size()) {
            throw new IllegalArgumentException("OAUTH_RESOURCE_FENCE_SET_INVALID");
        }
        var ordered = resources.stream().sorted(Comparator.comparing(OAuthResourceBO::getId)).toList();
        return transaction(60).execute(outer -> {
            for (OAuthResourceBO resource : ordered) {
                if (!fences.fenceCurrent(platform, resource)) {
                    throw new TransientDataAccessResourceException("OAuth resource is not yet visible at its expected version");
                }
            }
            return transaction(45).execute(inner -> action.get());
        });
    }

    private TransactionTemplate transaction(int timeout) {
        var template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template.setTimeout(timeout);
        return template;
    }
}
