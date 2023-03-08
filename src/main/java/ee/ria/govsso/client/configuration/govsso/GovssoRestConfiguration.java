package ee.ria.govsso.client.configuration.govsso;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.stream.Stream;

@Configuration
public class GovssoRestConfiguration {

    @Bean
    RestTemplate govssoRestTemplate(GovssoProperties properties)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException {
        SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(
                        properties.trustStore().getURL(),
                        properties.trustStorePassword().toCharArray())
                .build();
        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
        @SuppressWarnings("resource")
        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();
        RestTemplate restTemplate = new RestTemplateBuilder()
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(httpClient))
                .build();
        restTemplate.setMessageConverters(
                Stream.concat(
                        Stream.of(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()),
                        restTemplate.getMessageConverters().stream()
                ).toList()
        );
        return restTemplate;
    }

}
