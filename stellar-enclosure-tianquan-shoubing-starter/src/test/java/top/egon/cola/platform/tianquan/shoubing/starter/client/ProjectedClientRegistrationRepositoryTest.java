package top.egon.cola.platform.tianquan.shoubing.starter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProjectedClientRegistrationRepositoryTest {

    private static final String ID = "orders-client";
    private static final String ISSUER = "https://identity.example/tenants/1001";
    private static final String ERROR = "IDP_PROJECTED_CLIENT_REGISTRATIONS_UNAVAILABLE";

    @TempDir
    Path directory;

    @Test
    void loadsCanonicalBasicRegistrationsAndVersionFromOneDocumentWithNoRegisteredScope() throws Exception {
        Path file = write(document(2L, "private-value"));
        var repository = repository(file, Map.of());
        repository.verifyAvailable(Set.of(ID));

        repository.withSnapshot(ID, () -> {
            var registration = repository.findByRegistrationId(ID);
            assertThat(registration.getRegistrationId()).isEqualTo(ID);
            assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(ISSUER);
            assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(ISSUER + "/oauth2/token");
            assertThat(registration.getClientSecret()).isEqualTo("private-value");
            assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
            assertThat(registration.getScopes()).isEmpty();
            assertThat(repository.credentialVersion(ID)).isEqualTo(2L);
            return null;
        });
        assertThat(repository.findByRegistrationId("unknown")).isNull();
    }

    @Test
    void rotationWaitsForCompleteLeasesAndRetiresBeforePublishingNewRegistration() throws Exception {
        Path file = write(document(1L, "old-value"));
        var repository = repository(file, Map.of(ID, 1L));
        repository.verifyAvailable();
        AtomicInteger retirements = new AtomicInteger();
        Runnable unsubscribe = repository.onRetirement(changed -> {
            assertThat(changed).containsExactly(ID);
            assertThat(repository.findByRegistrationId(ID).getClientSecret()).isEqualTo("old-value");
            retirements.incrementAndGet();
        });
        try (var worker = Executors.newSingleThreadExecutor()) {
            repository.withSnapshot(ID, () -> {
                try {
                    Files.writeString(file, document(2L, "new-value"));
                    CountDownLatch entered = new CountDownLatch(1);
                    var publication = worker.submit(() -> {
                        entered.countDown();
                        repository.verifyAvailable();
                    });
                    assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
                    assertThatThrownBy(() -> publication.get(100, TimeUnit.MILLISECONDS))
                            .isInstanceOf(TimeoutException.class);
                    assertThat(repository.findByRegistrationId(ID).getClientSecret()).isEqualTo("old-value");
                    assertThat(repository.credentialVersion(ID)).isEqualTo(1L);
                    assertThat(retirements).hasValue(0);
                } catch (Exception failure) {
                    throw new AssertionError(failure);
                }
                return null;
            });
        }
        repository.withSnapshot(ID, () -> {
            assertThat(repository.findByRegistrationId(ID).getClientSecret()).isEqualTo("new-value");
            assertThat(repository.credentialVersion(ID)).isEqualTo(2L);
            return null;
        });
        assertThat(retirements).hasValue(1);
        unsubscribe.run();
        Files.writeString(file, document(3L, "third-value"));
        repository.verifyAvailable();
        assertThat(retirements).hasValue(1);
    }

    @Test
    void unchangedDocumentCanServeAnotherLeaseWhileAnAcquisitionIsStillInProgress() throws Exception {
        Path file = write(document(1L, "active-value"));
        var repository = repository(file, Map.of());
        repository.verifyAvailable();
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var acquisition = workers.submit(() -> repository.withSnapshot(ID, () -> {
                held.countDown();
                try {
                    assertThat(finish.await(3, TimeUnit.SECONDS)).isTrue();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(interrupted);
                }
                return repository.credentialVersion(ID);
            }));
            try {
                assertThat(held.await(2, TimeUnit.SECONDS)).isTrue();
                var second = workers.submit(() -> repository.withSnapshot(ID, () -> repository.credentialVersion(ID)));
                assertThat(second.get(1, TimeUnit.SECONDS)).isEqualTo(1L);
                assertThat(acquisition.isDone()).isFalse();
            } finally {
                finish.countDown();
            }
            assertThat(acquisition.get(2, TimeUnit.SECONDS)).isEqualTo(1L);
        }
    }

    @Test
    void rejectsSameVersionChangesRollbackAndDeletedIdentityRollbackWithoutReplacingGoodGeneration() throws Exception {
        Path file = write(document(2L, "active-value"));
        var repository = repository(file, Map.of());
        repository.verifyAvailable();
        for (String invalid : List.of(document(2L, "changed-value"), document(1L, "older-value"),
                document(2L, "active-value").replace("https://identity.example", "https://other.example"))) {
            Files.writeString(file, invalid);
            assertUnavailable(repository);
        }
        Files.writeString(file, document(2L, "active-value"));
        repository.verifyAvailable();
        assertThat(repository.findByRegistrationId(ID).getClientSecret()).isEqualTo("active-value");
        Files.writeString(file, "{\"registrations\":[]}");
        repository.verifyAvailable();
        assertThat(repository.findByRegistrationId(ID)).isNull();
        assertThatThrownBy(() -> repository.verifyAvailable(Set.of(ID))).hasMessage(ERROR);
        Files.writeString(file, document(1L, "older-value"));
        assertUnavailable(repository);
        Files.writeString(file, document(2L, "active-value"));
        assertUnavailable(repository);
        Files.writeString(file, document(3L, "next-value"));
        repository.verifyAvailable(Set.of(ID));
        assertThat(repository.findByRegistrationId(ID).getClientSecret()).isEqualTo("next-value");
    }

    @Test
    void rejectsUnknownDuplicateMissingMalformedAndOversizedMaterialWithoutSecretCauses() throws Exception {
        Path file = write(document(1L, "sensitive-private-value"));
        var repository = repository(file, Map.of());
        repository.verifyAvailable();
        String valid = document(1L, "sensitive-private-value");
        List<String> invalid = new ArrayList<>(List.of(
                valid.replace("\"registrations\":", "\"unknown\":true,\"registrations\":"),
                valid.replace("\"clientSecret\":", "\"extra\":true,\"clientSecret\":"),
                valid.replace("\"clientSecret\":", "\"clientSecret\":\"another\",\"clientSecret\":"),
                valid.replace("\"clientSecret\":\"sensitive-private-value\",", ""),
                valid.replace("sensitive-private-value", " "),
                valid.replace("\"credentialVersion\":1", "\"credentialVersion\":1.0"),
                valid.replace("\"credentialVersion\":1", "\"credentialVersion\":-1"),
                valid.replace("\"credentialVersion\":1", "\"credentialVersion\":9223372036854775808"),
                valid.replace("https://", "http://"),
                valid.replace(ISSUER + "/oauth2/token", "https://wrong.example/oauth2/token"),
                valid + " {}", "{\"registrations\":[null]}",
                "{\"registrations\":[" + valid.substring(valid.indexOf('[') + 1, valid.lastIndexOf(']'))
                        + "," + valid.substring(valid.indexOf('[') + 1, valid.lastIndexOf(']')) + "]}"));
        for (String value : invalid) {
            Files.writeString(file, value);
            assertUnavailable(repository);
        }
        Files.write(file, new byte[] { '{', (byte) 0xc3, (byte) 0x28, '}' });
        assertUnavailable(repository);
        Files.writeString(file, " ".repeat(1024 * 1024 + 1));
        assertUnavailable(repository);
        Files.delete(file);
        assertUnavailable(repository);
        Files.writeString(file, valid);
        repository.verifyAvailable();
        assertThat(repository.findByRegistrationId(ID).getClientSecret()).isEqualTo("sensitive-private-value");
    }

    @Test
    void floorsAreCopiedAndWholeBundleValidationPrecedesAnyPublication() throws Exception {
        Path file = write(document(2L, "active-value"));
        Map<String, Long> floors = new HashMap<>(Map.of(ID, 2L));
        var repository = repository(file, floors);
        floors.put(ID, 100L);
        repository.verifyAvailable(Set.of(ID));
        Files.writeString(file, document(1L, "older-value"));
        assertUnavailable(repository);
        String partial = document(3L, "next-value");
        String entry = partial.substring(partial.indexOf('[') + 1, partial.lastIndexOf(']'));
        Files.writeString(file, "{\"registrations\":[" + entry + ",{\"registrationId\":\"broken\"}]}");
        assertUnavailable(repository);
        Files.writeString(file, document(2L, "active-value"));
        repository.verifyAvailable(Set.of(ID));
    }

    @Test
    void readsKubeletStyleGenerationSymlinkAndRejectsEscapes() throws Exception {
        Path generation = Files.createDirectory(directory.resolve("..generation"));
        Files.writeString(generation.resolve("clients.json"), document(1L, "first-value"));
        Files.createSymbolicLink(directory.resolve("..data"), Path.of("..generation"));
        Path file = Files.createSymbolicLink(directory.resolve("clients.json"), Path.of("..data/clients.json"));
        var repository = repository(file, Map.of());
        repository.verifyAvailable(Set.of(ID));
        Path outside = Files.createTempFile("idp-projection-outside-", ".json");
        try {
            Files.writeString(outside, document(2L, "outside-value"));
            Files.delete(file);
            Files.createSymbolicLink(file, outside);
            assertUnavailable(repository);
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    private Path write(String contents) throws Exception {
        Path file = directory.resolve("clients.json");
        Files.writeString(file, contents, StandardCharsets.UTF_8);
        return file;
    }

    private ProjectedClientRegistrationRepository repository(Path file, Map<String, Long> floors) {
        return new ProjectedClientRegistrationRepository(file, new ObjectMapper(), floors);
    }

    private static void assertUnavailable(ProjectedClientRegistrationRepository repository) {
        assertThatThrownBy(repository::verifyAvailable).isExactlyInstanceOf(IllegalStateException.class)
                .hasMessage(ERROR).hasNoCause();
    }

    private static String document(long version, String secret) {
        return """
                {"registrations":[{"registrationId":"%s","issuer":"%s","tokenUri":"%s/oauth2/token",
                "clientId":"orders-service","clientSecret":"%s","credentialVersion":%d}]}
                """.formatted(ID, ISSUER, ISSUER, secret, version);
    }
}
