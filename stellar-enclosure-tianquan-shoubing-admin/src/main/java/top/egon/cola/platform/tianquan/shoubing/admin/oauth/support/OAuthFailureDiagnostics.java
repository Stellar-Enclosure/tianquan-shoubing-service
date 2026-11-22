package top.egon.cola.platform.tianquan.shoubing.admin.oauth.support;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.event.Level;

/** Records failure locations without exposing exception messages, credentials or request values. */
public final class OAuthFailureDiagnostics {
    private OAuthFailureDiagnostics() { }

    public static void failure(Logger logger, String operation, Throwable failure) {
        record(logger, Level.WARN, operation, failure);
    }

    public static void rejection(Logger logger, String operation, Throwable failure) {
        record(logger, Level.DEBUG, operation, failure);
    }

    private static void record(Logger logger, Level level, String operation, Throwable failure) {
        if (!logger.isEnabledForLevel(level)) { return; }
        var types = new ArrayList<String>();
        var origins = new ArrayList<String>();
        String sqlState = null;
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < 16; depth++, cause = cause.getCause()) {
            types.add(cause.getClass().getSimpleName());
            origins.add(Arrays.stream(cause.getStackTrace())
                    .filter(frame -> frame.getClassName().startsWith("top.egon.cola.platform.tianquan.shoubing."))
                    .limit(3).map(frame -> frame.getClassName() + "#" + frame.getMethodName() + ":" + frame.getLineNumber())
                    .collect(java.util.stream.Collectors.joining(" > ")));
            if (cause instanceof SQLException sql) { sqlState = sql.getSQLState(); }
        }
        logger.atLevel(level).log("OAuth operation failed operation={} causeTypes={} origins={} sqlState={}",
                operation, types, origins, sqlState);
    }
}
