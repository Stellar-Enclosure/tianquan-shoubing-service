package top.egon.cola.platform.tianquan.shoubing.starter.client;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpProjectedFileComponent;

/**
 * Atomically publishes complete SERVICE registrations from a trusted Secret projection.
 *
 * <p>The facade holds a read lease across key selection, Spring's repeated repository lookups,
 * and token return. A replacement waits for those calls and retires their caches before publication.
 * Credentials are never obtained from dynamic application configuration.</p>
 */
@Slf4j
public final class ProjectedClientRegistrationRepository implements ClientRegistrationRepository {

    private static final int MAX_DOCUMENT_BYTES = 1024 * 1024;
    private static final int MAX_REGISTRATIONS = 1000;
    private static final int MAX_OBSERVED_REGISTRATIONS = 10_000;
    private static final Set<String> REGISTRATION_FIELDS = Set.of(
            "registrationId", "issuer", "tokenUri", "clientId", "clientSecret", "credentialVersion");
    private static final String UNAVAILABLE = "IDP_PROJECTED_CLIENT_REGISTRATIONS_UNAVAILABLE";

    private final Path file;
    private final ObjectReader reader;
    private final Map<String, Long> credentialVersionFloors;
    private final ReentrantReadWriteLock publication = new ReentrantReadWriteLock(true);
    private final Object reloadLock = new Object();
    private final CopyOnWriteArrayList<Consumer<Set<String>>> retirementListeners = new CopyOnWriteArrayList<>();
    private final Map<String, RevisionVO> observed = new HashMap<>();
    private Map<String, RegistrationSnapshotVO> current;
    private String acceptedDocumentDigest;

    /** Creates a projection source; explicit startup verification is required before serving calls. */
    public ProjectedClientRegistrationRepository(Path file, ObjectMapper mapper,
            Map<String, Long> credentialVersionFloors) {
        if (file == null || !file.isAbsolute() || !file.normalize().equals(file)
                || file.getParent() == null || mapper == null || credentialVersionFloors == null
                || credentialVersionFloors.size() > MAX_REGISTRATIONS) {
            throw new IllegalArgumentException("IDP_PROJECTED_CLIENT_REGISTRATIONS_CONFIGURATION_INVALID");
        }
        Map<String, Long> floors = new HashMap<>();
        credentialVersionFloors.forEach((id, version) -> {
            if (!validRegistrationId(id) || version == null || version < 0) {
                throw new IllegalArgumentException("IDP_PROJECTED_CLIENT_REGISTRATIONS_CONFIGURATION_INVALID");
            }
            floors.put(id, version);
        });
        this.file = file;
        this.credentialVersionFloors = Map.copyOf(floors);
        this.reader = mapper.copy().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readerFor(JsonNode.class);
    }

    /** Loads and validates one complete projection without disclosing file or parser details. */
    public void verifyAvailable() {
        verifyAvailable(Set.of());
    }

    /** Verifies all deployed registration references against one fresh generation. */
    public void verifyAvailable(Set<String> requiredRegistrations) {
        Objects.requireNonNull(requiredRegistrations, "requiredRegistrations");
        Set<String> required = Set.copyOf(requiredRegistrations);
        if (required.size() > MAX_REGISTRATIONS || required.stream().anyMatch(id -> !validRegistrationId(id))) {
            throw unavailable();
        }
        refresh();
        publication.readLock().lock();
        try {
            if (current == null || !current.keySet().containsAll(required)) {
                throw unavailable();
            }
        } finally {
            publication.readLock().unlock();
        }
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        if (publication.getReadHoldCount() > 0 || publication.isWriteLockedByCurrentThread()) {
            return registration(registrationId);
        }
        refresh();
        publication.readLock().lock();
        try {
            return registration(registrationId);
        } finally {
            publication.readLock().unlock();
        }
    }

    /** Keeps all Spring repository reads in a synchronous authorization on the same generation. */
    <T> T withSnapshot(String registrationId, Supplier<T> action) {
        Objects.requireNonNull(action, "action");
        if (publication.getReadHoldCount() == 0) {
            refresh();
        }
        publication.readLock().lock();
        try {
            if (registration(registrationId) == null) {
                throw unavailable();
            }
            return action.get();
        } finally {
            publication.readLock().unlock();
        }
    }

    /** Acquires only the accepted-generation read lease for eviction, never for credential issuance. */
    void withCurrentSnapshot(Runnable cleanup) {
        Objects.requireNonNull(cleanup, "cleanup");
        publication.readLock().lock();
        try {
            cleanup.run();
        } finally {
            publication.readLock().unlock();
        }
    }

    long credentialVersion(String registrationId) {
        if (publication.getReadHoldCount() == 0) {
            throw unavailable();
        }
        RegistrationSnapshotVO snapshot = current == null ? null : current.get(registrationId);
        if (snapshot == null) {
            throw unavailable();
        }
        return snapshot.credentialVersion();
    }

    /** The listener executes before publication while the previous registrations are still visible. */
    Runnable onRetirement(Consumer<Set<String>> listener) {
        Objects.requireNonNull(listener, "listener");
        retirementListeners.add(listener);
        return () -> retirementListeners.remove(listener);
    }

    private ClientRegistration registration(String registrationId) {
        RegistrationSnapshotVO snapshot = current == null ? null : current.get(registrationId);
        return snapshot == null ? null : snapshot.registration();
    }

    private void refresh() {
        if (publication.getReadHoldCount() > 0 || publication.isWriteLockedByCurrentThread()) {
            return;
        }
        synchronized (reloadLock) {
            ProjectionCandidateVO loaded = readCandidate();
            if (loaded == null) {
                return;
            }
            Map<String, RegistrationSnapshotVO> candidate = loaded.registrations();
            publication.writeLock().lock();
            try {
                validateRevisions(candidate);
                Set<String> changed = changedRegistrations(candidate);
                if (!changed.isEmpty()) {
                    Set<String> retiring = Set.copyOf(changed);
                    try {
                        retirementListeners.forEach(listener -> listener.accept(retiring));
                    } catch (RuntimeException failure) {
                        throw unavailable();
                    }
                }
                candidate.forEach((id, snapshot) -> observed.put(id,
                        new RevisionVO(snapshot.credentialVersion(), snapshot.fingerprint())));
                current = candidate;
                acceptedDocumentDigest = loaded.documentDigest();
            } finally {
                publication.writeLock().unlock();
            }
        }
    }

    private ProjectionCandidateVO readCandidate() {
        byte[] bytes = null;
        try {
            bytes = IdpProjectedFileComponent.read(file, MAX_DOCUMENT_BYTES);
            String documentDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (documentDigest.equals(acceptedDocumentDigest)) {
                return null;
            }
            requireUtf8(bytes);
            JsonNode root = reader.readValue(bytes);
            requireFields(root, Set.of("registrations"));
            JsonNode registrations = root.get("registrations");
            if (!registrations.isArray() || registrations.size() > MAX_REGISTRATIONS) {
                throw unavailable();
            }
            Map<String, RegistrationSnapshotVO> candidate = new LinkedHashMap<>();
            for (JsonNode node : registrations) {
                requireFields(node, REGISTRATION_FIELDS);
                String id = text(node, "registrationId", 128);
                String issuer = text(node, "issuer", 2048);
                String endpoint = text(node, "tokenUri", 2048);
                String clientId = text(node, "clientId", 256);
                String secret = text(node, "clientSecret", 8192);
                JsonNode versionNode = node.get("credentialVersion");
                if (!validRegistrationId(id) || !versionNode.isIntegralNumber() || !versionNode.canConvertToLong()
                        || versionNode.longValue() < credentialVersionFloors.getOrDefault(id, 0L)) {
                    throw unavailable();
                }
                long version = versionNode.longValue();
                URI issuerUri = canonicalHttps(issuer);
                URI endpointUri = canonicalHttps(endpoint);
                if (!issuerUri.getHost().equalsIgnoreCase(endpointUri.getHost())
                        || effectivePort(issuerUri) != effectivePort(endpointUri)
                        || endpointUri.getRawPath() == null || endpointUri.getRawPath().isEmpty()) {
                    throw unavailable();
                }
                ClientRegistration registration = ClientRegistration.withRegistrationId(id)
                        .issuerUri(issuer).tokenUri(endpoint).clientId(clientId).clientSecret(secret)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).build();
                String fingerprint = fingerprint(id, issuer, endpoint, clientId, secret);
                if (candidate.putIfAbsent(id, new RegistrationSnapshotVO(registration, version, fingerprint)) != null) {
                    throw unavailable();
                }
            }
            return new ProjectionCandidateVO(Map.copyOf(candidate), documentDigest);
        } catch (Exception invalid) {
            // JSON exceptions can retain source snippets containing the Secret: intentionally discard causes.
            throw unavailable();
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    private void validateRevisions(Map<String, RegistrationSnapshotVO> candidate) {
        Set<String> identities = new HashSet<>(observed.keySet());
        identities.addAll(candidate.keySet());
        if (identities.size() > MAX_OBSERVED_REGISTRATIONS) {
            throw unavailable();
        }
        candidate.forEach((id, snapshot) -> {
            RevisionVO previous = observed.get(id);
            if (previous != null && (snapshot.credentialVersion() < previous.credentialVersion()
                    || current != null && !current.containsKey(id)
                    && snapshot.credentialVersion() <= previous.credentialVersion()
                    || snapshot.credentialVersion() == previous.credentialVersion()
                    && !snapshot.fingerprint().equals(previous.fingerprint()))) {
                throw unavailable();
            }
        });
    }

    private Set<String> changedRegistrations(Map<String, RegistrationSnapshotVO> candidate) {
        if (current == null) {
            return Set.of();
        }
        Set<String> changed = new HashSet<>();
        current.forEach((id, previous) -> {
            RegistrationSnapshotVO replacement = candidate.get(id);
            if (replacement == null || replacement.credentialVersion() != previous.credentialVersion()
                    || !replacement.fingerprint().equals(previous.fingerprint())) {
                changed.add(id);
            }
        });
        return changed;
    }

    private static void requireUtf8(byte[] bytes) throws CharacterCodingException {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
    }

    private static void requireFields(JsonNode node, Set<String> expected) {
        if (node == null || !node.isObject() || node.size() != expected.size()) {
            throw unavailable();
        }
        node.fieldNames().forEachRemaining(name -> {
            if (!expected.contains(name)) {
                throw unavailable();
            }
        });
    }

    private static String text(JsonNode node, String field, int maximum) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.textValue().isBlank()
                || value.textValue().length() > maximum || value.textValue().codePoints().anyMatch(Character::isISOControl)) {
            throw unavailable();
        }
        return value.textValue();
    }

    private static boolean validRegistrationId(String id) {
        return id != null && id.matches("[A-Za-z0-9._-]{1,128}");
    }

    private static URI canonicalHttps(String value) {
        URI uri = URI.create(value);
        if (!uri.isAbsolute() || uri.isOpaque() || !"https".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || uri.getPort() == 0 || uri.getPort() > 65535 || !uri.normalize().equals(uri)
                || !uri.toASCIIString().equals(value)) {
            throw unavailable();
        }
        return uri;
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    private static String fingerprint(String... dimensions) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (String dimension : dimensions) {
            byte[] value = dimension.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
            digest.update(value);
            Arrays.fill(value, (byte) 0);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException(UNAVAILABLE);
    }

    private record RegistrationSnapshotVO(ClientRegistration registration, long credentialVersion, String fingerprint) {
        @Override
        public String toString() {
            return "RegistrationSnapshotVO[credentialVersion=" + credentialVersion + "]";
        }
    }

    private record RevisionVO(long credentialVersion, String fingerprint) {
    }

    private record ProjectionCandidateVO(Map<String, RegistrationSnapshotVO> registrations, String documentDigest) {
    }
}
