package top.egon.cola.platform.tianquan.shoubing.admin.support.tianshu;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Publishes one validated startup policy for the lifetime of the process.
 * The historical class name remains source compatible; the snapshot has no mutation entry point.
 */
public final class AtomicIdpRuntimePolicy implements IdpRuntimePolicy {

    public static final String ACCESS_TOKEN_TTL_KEY =
            "tianquan-shoubing.token.access-ttl";
    public static final String REFRESH_TOKEN_TTL_KEY =
            "tianquan-shoubing.token.refresh-ttl";
    public static final String AUTHORIZATION_CODE_TTL_KEY =
            "tianquan-shoubing.authorization-code.ttl";
    public static final String MAXIMUM_LOGIN_FAILURES_KEY =
            "tianquan-shoubing.login.max-failures";
    public static final String LOGIN_LOCK_DURATION_KEY =
            "tianquan-shoubing.login.lock-duration";
    public static final String PASSWORD_MAXIMUM_CONCURRENCY_KEY =
            "tianquan-shoubing.password.max-concurrency";

    public static final Set<String> CONFIG_KEYS = Set.of(
            ACCESS_TOKEN_TTL_KEY,
            REFRESH_TOKEN_TTL_KEY,
            AUTHORIZATION_CODE_TTL_KEY,
            MAXIMUM_LOGIN_FAILURES_KEY,
            LOGIN_LOCK_DURATION_KEY,
            PASSWORD_MAXIMUM_CONCURRENCY_KEY);

    private static final Pattern UNSIGNED_INTEGER = Pattern.compile("[0-9]+");
    private static final Map<String, Long> DEFAULT_VALUES = Map.of(
            ACCESS_TOKEN_TTL_KEY, 900L,
            REFRESH_TOKEN_TTL_KEY, 604800L,
            AUTHORIZATION_CODE_TTL_KEY, 60L,
            MAXIMUM_LOGIN_FAILURES_KEY, 5L,
            LOGIN_LOCK_DURATION_KEY, 900L,
            PASSWORD_MAXIMUM_CONCURRENCY_KEY, 8L);

    private final Snapshot snapshot;

    public AtomicIdpRuntimePolicy() {
        this(DEFAULT_VALUES, 0L);
    }

    AtomicIdpRuntimePolicy(Map<String, Long> startupValues, long revision) {
        if (!startupValues.keySet().equals(CONFIG_KEYS) || revision < 0L) {
            throw new IllegalArgumentException("IDP_POLICY_STARTUP_VALUES_INVALID");
        }
        Map<String, Long> versions = new LinkedHashMap<>();
        CONFIG_KEYS.stream().sorted().forEach(key -> versions.put(key, revision));
        snapshot = new Snapshot(
                Duration.ofSeconds(startupValues.get(ACCESS_TOKEN_TTL_KEY)),
                Duration.ofSeconds(startupValues.get(REFRESH_TOKEN_TTL_KEY)),
                Duration.ofSeconds(startupValues.get(AUTHORIZATION_CODE_TTL_KEY)),
                integer(startupValues.get(MAXIMUM_LOGIN_FAILURES_KEY)),
                Duration.ofSeconds(startupValues.get(LOGIN_LOCK_DURATION_KEY)),
                integer(startupValues.get(PASSWORD_MAXIMUM_CONCURRENCY_KEY)),
                versions);
    }

    @Override
    public Snapshot current() {
        return snapshot;
    }

    static long defaultValue(String key) {
        return DEFAULT_VALUES.get(key);
    }

    /** Accepts exact integral typed baseline numbers and the existing unsigned string syntax. */
    static long numericValue(Object value) {
        try {
            if (value instanceof String text && UNSIGNED_INTEGER.matcher(text).matches()) {
                return Long.parseLong(text);
            }
            if (value instanceof Number number) {
                long parsed = new BigDecimal(number.toString()).longValueExact();
                if (parsed >= 0L) return parsed;
            }
        } catch (RuntimeException invalid) {
            // Conversion failures can contain the raw input; do not retain them as causes.
            throw new IllegalArgumentException("IDP_POLICY_INTEGER_INVALID");
        }
        throw new IllegalArgumentException("IDP_POLICY_INTEGER_INVALID");
    }

    private static int integer(long value) {
        try {
            return Math.toIntExact(value);
        } catch (ArithmeticException overflow) {
            throw new IllegalArgumentException("INTEGER_OUT_OF_RANGE");
        }
    }
}
