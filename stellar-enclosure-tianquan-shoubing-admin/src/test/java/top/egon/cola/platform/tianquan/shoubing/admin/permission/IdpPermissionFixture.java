package top.egon.cola.platform.tianquan.shoubing.admin.permission;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.authorization.*;
import top.egon.cola.platform.tianquan.jianshen.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.contract.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;

final class IdpPermissionFixture {
    static final Instant NOW=Instant.parse("2026-10-25T00:00:00Z");
    static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
    static final String ARTIFACT="a".repeat(64);
    static final CatalogScope SCOPE=new CatalogScope("10","20","xingyuan","tianquan-shoubing","default","test");
    static final IdentityPrincipal USER=new IdentityPrincipal("30","20","40",Set.of("https://api.example/identity"),NOW.minusSeconds(10),NOW.plusSeconds(300),AuthenticationContext.password());
    static PermissionManifest fragment()throws Exception {
        return new PermissionManifestReader().read(new ObjectMapper().readValue(Files.readString(Path.of("target/classes/META-INF/permissions/fragment-v1.json")),new TypeReference<Map<String,Object>>(){}));
    }
    static PermissionManifest manifest()throws Exception {
        var source=fragment();var producer=source.producer();
        // Test-local completion exercises executors; the production FULL is checked from the packaged JAR separately.
        return new PermissionManifest(source.schemaVersion(),source.application(),new PermissionManifest.Producer(producer.id(),producer.kind(),PermissionManifest.SnapshotMode.FULL,
                producer.ownedKeyPrefixes(),producer.expectedModules(),producer.scannedModules(),false),source.artifact(),source.permissionDefinitions(),source.permissionReferences(),source.resources(),source.resourceReferences(),source.messages());
    }
    static SystemAuthorizationSnapshot snapshot(PermissionManifest manifest,Set<String> codes) {
        var d=new PermissionManifestCanonicalizer().digests(manifest);
        var view=new EffectivePermissionSnapshot("https://idp.example/tenants/20",USER.subject(),SCOPE,"1","2","3",new EffectivePermissionSnapshot.ActiveRoleContext("tianquan-shoubing",List.of("50"),List.of("50")),codes.stream().sorted().toList(),NOW.plusSeconds(30));
        return new SystemAuthorizationSnapshot("20",USER.subject(),"60","tianquan-shoubing",2,3,List.of("50"),null,null,codes,manifest.resources().stream().map(PermissionManifest.ResourceDefinition::key).collect(java.util.stream.Collectors.toSet()),Map.of(),Map.of(),"checksum",NOW,view.snapshotExpiresAt(),view,new RuntimePolicyBinding("tianquan-shoubing-java","1",ARTIFACT,d.policyDigest(),d.manifestDigest()));
    }
    static void authenticate(PermissionManifest manifest,Set<String> codes,Set<String> scopes) {
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(new Rbac3AuthenticationToken(new Rbac3UserDetails(USER,snapshot(manifest,codes)),scopes.stream().map(s->new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_"+s)).toList()));
    }
}
