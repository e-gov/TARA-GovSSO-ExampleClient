package ee.ria.govsso.client.tara.configuration;

import ee.ria.govsso.client.oauth2.OAuth2RestOperationsFactory;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
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
@ConditionalOnTara
public class TaraRestConfiguration {

    @Bean
    RestOperations taraRestOperations(TaraProperties properties)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException {
        SSLContext sslContext = createSslContext(properties);
        return OAuth2RestOperationsFactory.create(sslContext);
    }

    private static SSLContext createSslContext(TaraProperties properties)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException {
        return SSLContextBuilder.create()
                .loadTrustMaterial(
                        properties.trustStore().getURL(),
                        properties.trustStorePassword().toCharArray())
                .build();
    }


}
