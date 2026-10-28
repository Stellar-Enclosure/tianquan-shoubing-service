package top.egon.cola.platform.tianquan.shoubing.admin.support.outbox;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import top.egon.cola.component.common.mybatis.routing.EgonColaRouteQuery;
import top.egon.cola.component.common.mybatis.routing.EgonColaRoutingProfileBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaRoutingProfileBO.PartitionKeyBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy;
import top.egon.cola.component.outbox.api.OutboxShardIdentity;

/** Derives a stable Outbox identity from the business partition before its first write. */
public final class OAuthOutboxIdentity {
    private static final Pattern SHARD_PREFIX = Pattern.compile("s1_[0-9a-f]{8}_.+");
    private final Map<String, EgonColaRoutingProfileBO> profiles;
    private final Map<Integer, String> slots;
    private final long platformPartition;

    public OAuthOutboxIdentity(Map<String, EgonColaRoutingProfileBO> profiles, long platformPartition) {
        if (platformPartition <= 0) throw new IllegalArgumentException("OAUTH_OUTBOX_TENANT_INVALID");
        this.platformPartition = platformPartition;
        this.profiles = Map.copyOf(Objects.requireNonNull(profiles, "profiles"));
        var profile = Objects.requireNonNull(profiles.get("egon_cola_outbox_message"), "outbox profile");
        this.slots = switch (profile.kind()) {
            case SINGLE -> Map.of(0, profile.actualNodes().get(new PartitionKeyBO(0, 0)).getFirst().group());
            case TECHNICAL_GROUP -> profile.tenantSlotMap();
            default -> throw new IllegalArgumentException("OAUTH_OUTBOX_TOPOLOGY_INVALID");
        };
    }

    private OAuthOutboxIdentity() { this.profiles = Map.of(); this.slots = Map.of(0, "legacy"); this.platformPartition = 1; }
    public static OAuthOutboxIdentity singleGroup() { return new OAuthOutboxIdentity(); }

    public Scope forPlatform(String logicalTable) { return forTenant(logicalTable, platformPartition); }

    public Scope forTenant(String logicalTable, long tenantId) {
        if (tenantId <= 0) throw new IllegalArgumentException("OAUTH_OUTBOX_TENANT_INVALID");
        if (profiles.isEmpty()) return new Scope(0, slots);
        var profile = Objects.requireNonNull(profiles.get(logicalTable), "business profile");
        var query = new EgonColaRouteQuery(logicalTable, tenantId, List.of(), EgonColaRouteQuery.OperationEnum.ROUTE_CANDIDATES, false);
        var groups = EgonColaTwoLevelRouteStrategy.routeCandidates(profile, query).targets().stream()
                .map(target -> target.group()).distinct().toList();
        if (groups.size() != 1) throw new IllegalStateException("OAUTH_OUTBOX_BUSINESS_GROUP_AMBIGUOUS");
        int slot = slots.entrySet().stream().filter(entry -> entry.getValue().equals(groups.getFirst()))
                .map(Map.Entry::getKey).findFirst().orElseThrow(() -> new IllegalStateException("OAUTH_OUTBOX_GROUP_MISSING"));
        return new Scope(slot, slots);
    }

    public record Scope(int slot, Map<Integer, String> slots) {
        public Scope {
            slots = Map.copyOf(Objects.requireNonNull(slots, "slots"));
            if (slot < 0 || !slots.containsKey(0) || !slots.containsKey(slot)) {
                throw new IllegalArgumentException("OAUTH_OUTBOX_GROUP_MISSING");
            }
        }
        public String messageId(String value) { return encode(value, 64); }
        public String idempotencyKey(String value) { return encode(value, 256); }

        private String encode(String value, int maxLength) {
            if (value == null || value.isBlank()) throw new IllegalArgumentException("OAUTH_OUTBOX_IDENTITY_REQUIRED");
            if (SHARD_PREFIX.matcher(value).matches()) {
                if (OutboxShardIdentity.slotOf(value, slots) != slot) throw new IllegalArgumentException("OAUTH_OUTBOX_IDENTITY_MISMATCH");
                if (value.length() > maxLength) throw new IllegalArgumentException("OAUTH_OUTBOX_IDENTITY_TOO_LONG");
                return value;
            }
            if (slot == 0 && value.length() <= maxLength) return value;
            String suffix = value.length() <= maxLength - 12 ? value : digest(value);
            return OutboxShardIdentity.forSlot(slot, suffix);
        }
    }

    private static String digest(String value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
