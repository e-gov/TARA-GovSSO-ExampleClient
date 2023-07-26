package ee.ria.govsso.client.oauth2;

import lombok.experimental.UtilityClass;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.util.List;
import java.util.stream.Stream;

@UtilityClass
public class OAuth2RestOperationsFactory {

    public static RestOperations create(SSLContext sslContext) {
        @SuppressWarnings("resource")
        HttpClient httpClient = HttpClients.custom()
                .setConnectionManager(createConnectionManager(sslContext))
                .build();
        RestTemplate restTemplate = new RestTemplateBuilder()
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(httpClient))
                .build();
        List<HttpMessageConverter<?>> additionalMessageConverters = List.of(
                new FormHttpMessageConverter(),
                new OAuth2ErrorHttpMessageConverter(),
                new OAuth2AccessTokenResponseHttpMessageConverter()
        );
        addMessageConverters(restTemplate, additionalMessageConverters);
        return restTemplate;
    }

    private static HttpClientConnectionManager createConnectionManager(SSLContext sslContext) {
        return PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build())
                .build();
    }

    private static void addMessageConverters(
            RestTemplate restTemplate,
            List<HttpMessageConverter<?>> additionalMessageConverters) {
        List<HttpMessageConverter<?>> httpMessageConverters = Stream.concat(
                additionalMessageConverters.stream(),
                restTemplate.getMessageConverters().stream()
        ).toList();
        restTemplate.setMessageConverters(httpMessageConverters);
    }


}
