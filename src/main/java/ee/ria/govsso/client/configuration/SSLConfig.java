package ee.ria.govsso.client.configuration;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@RequiredArgsConstructor
public class SSLConfig {

    private final Environment env;

    // TODO: better truststore configuration.
    // TODO: Oauth2 needs specific configuration, seems to ignore globally configured SslContext and RestTemplate beans.
    @PostConstruct
    private void configureSSL() {
        System.setProperty("javax.net.ssl.trustStore", env.getProperty("server.ssl.trust-store"));
        System.setProperty("javax.net.ssl.trustStorePassword", env.getProperty("server.ssl.trust-store-password"));
    }
}
