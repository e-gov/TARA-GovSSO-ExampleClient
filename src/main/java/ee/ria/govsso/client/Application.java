package ee.ria.govsso.client;

import ee.ria.govsso.client.startup.RequireAuthenticationProviderProfile;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
@ConfigurationPropertiesScan
public class Application extends SpringBootServletInitializer {

    // Support servlet container as described in https://docs.spring.io/spring-boot/docs/2.7.x/reference/htmlsingle/#howto.traditional-deployment.war
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class).initializers(RequireAuthenticationProviderProfile::check);
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(Application.class)
                .initializers(RequireAuthenticationProviderProfile::check)
                .run(args);
    }

}
