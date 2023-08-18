package ee.ria.govsso.client;

import ee.ria.govsso.client.startup.RequireAuthenticationProviderProfile;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class Application {

    public static void main(String[] args) {
        new SpringApplicationBuilder(Application.class)
                .initializers(RequireAuthenticationProviderProfile::check)
                .run(args);
    }

}
