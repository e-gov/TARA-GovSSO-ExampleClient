package ee.ria.govsso.client.oauth2;

import lombok.experimental.UtilityClass;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
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
        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
        @SuppressWarnings("resource")
        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
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
