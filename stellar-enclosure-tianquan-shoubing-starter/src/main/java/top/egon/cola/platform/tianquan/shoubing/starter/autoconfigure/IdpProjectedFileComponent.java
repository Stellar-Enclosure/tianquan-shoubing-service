package top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Reads one bounded document from a read-only Kubernetes projected volume. */
public final class IdpProjectedFileComponent {

    private IdpProjectedFileComponent() {
    }

    public static byte[] read(Path file, int maxBytes) throws IOException {
        if (file == null || !file.isAbsolute() || !file.equals(file.normalize()) || file.getParent() == null
                || maxBytes <= 0 || maxBytes >= Integer.MAX_VALUE) {
            throw new IOException("IDP_PROJECTION_LOCATION_INVALID");
        }
        try {
            Path root = file.getParent().toRealPath();
            // AtomicWriter replaces ..data, so resolve the complete generation before opening it.
            Path resolved = file.toRealPath();
            if (!resolved.startsWith(root) || !Files.isRegularFile(resolved, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("IDP_PROJECTION_FILE_OUTSIDE_VOLUME");
            }
            try (var input = Files.newInputStream(resolved, LinkOption.NOFOLLOW_LINKS)) {
                byte[] contents = input.readNBytes(maxBytes + 1);
                if (contents.length == 0 || contents.length > maxBytes) {
                    java.util.Arrays.fill(contents, (byte) 0);
                    throw new IOException("IDP_PROJECTION_FILE_SIZE_INVALID");
                }
                return contents;
            }
        } catch (IOException | SecurityException failure) {
            // Mount paths and Secret contents are operational details, so do not propagate provider text.
            throw new IOException("IDP_PROJECTION_FILE_UNAVAILABLE");
        }
    }
}
