package top.egon.cola.platform.tianquan.shoubing.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class IdpAdminApplication {

    public static void main(String[] args) {
        if (args.length > 0 && top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap.PermissionIdentityBootstrapCli.COMMAND.equals(args[0])) {
            System.exit(top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap.PermissionIdentityBootstrapCli.run(args));
            return;
        }
        SpringApplication.run(IdpAdminApplication.class, args);
    }
}
