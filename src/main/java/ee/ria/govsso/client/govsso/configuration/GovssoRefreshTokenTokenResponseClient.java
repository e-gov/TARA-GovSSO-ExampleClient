package ee.ria.govsso.client.govsso.configuration;

import ee.ria.govsso.client.govsso.configuration.condition.ConditionalOnGovsso;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Based on {@link org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient},
 * but does not use access_token.
 */
@Component
@ConditionalOnGovsso
public class GovssoRefreshTokenTokenResponseClient
        implements OAuth2AccessTokenResponseClient<GovssoRefreshTokenTokenResponseClient.Request> {

    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

    private final RestOperations restOperations;

    public GovssoRefreshTokenTokenResponseClient(@Qualifier("govssoRestOperations") RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(@NonNull Request request) {
        RequestEntity<?> requestEntity = toRequestEntity(request);
        try {
            return this.restOperations.exchange(requestEntity, OAuth2AccessTokenResponse.class).getBody();
        }
        catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
                            + ex.getMessage(),
                    null);
            throw new OAuth2AuthorizationException(oauth2Error, ex);
        }
    }

    private RequestEntity<?> toRequestEntity(Request request) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        params.add(OAuth2ParameterNames.REFRESH_TOKEN, request.getOAuth2RefreshToken().getTokenValue());
        if (request.getScope() != null) {
            params.add(OAuth2ParameterNames.SCOPE, request.getScope());
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
        headers.setBasicAuth(
                request.getClientRegistration().getClientId(), request.getClientRegistration().getClientSecret(),
                UTF_8);

        URI uri = UriComponentsBuilder
                .fromUriString(request.getClientRegistration().getProviderDetails().getTokenUri())
                .build()
                .toUri();

        return new RequestEntity<>(params, headers, HttpMethod.POST, uri);
    }


    @Getter
    @ToString
    @EqualsAndHashCode(callSuper = true)
    public static class Request extends AbstractOAuth2AuthorizationGrantRequest {

        private final OAuth2RefreshToken oAuth2RefreshToken;
        private final String scope;

        public Request(ClientRegistration clientRegistration, OAuth2RefreshToken oAuth2RefreshToken, String scope) {
            super(AuthorizationGrantType.REFRESH_TOKEN, clientRegistration);
            this.oAuth2RefreshToken = oAuth2RefreshToken;
            this.scope = scope;
        }
    }

}
