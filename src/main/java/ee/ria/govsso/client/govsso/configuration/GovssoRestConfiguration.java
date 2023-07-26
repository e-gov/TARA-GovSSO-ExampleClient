package ee.ria.govsso.client.govsso.configuration;

import ee.ria.govsso.client.govsso.configuration.condition.ConditionalOnGovsso;
import ee.ria.govsso.client.oauth2.OAuth2RestOperationsFactory;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestOperations;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
@ConditionalOnGovsso
public class GovssoRestConfiguration {

    @Bean
    RestOperations govssoRestOperations(GovssoProperties properties)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException {
        SSLContext sslContext = createSslContext(properties);
        return OAuth2RestOperationsFactory.create(sslContext);
    }

    private SSLContext createSslContext(GovssoProperties properties)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException {
        return SSLContextBuilder.create()
                .loadTrustMaterial(
                        properties.trustStore().getURL(),
                        properties.trustStorePassword().toCharArray())
                .build();
    }

}
