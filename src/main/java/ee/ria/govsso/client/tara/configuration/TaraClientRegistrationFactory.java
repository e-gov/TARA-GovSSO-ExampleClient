package ee.ria.govsso.client.tara.configuration;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

@Component
@ConditionalOnTara
public class TaraClientRegistrationFactory {

    private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

    private final RestOperations restOperations;

    public TaraClientRegistrationFactory(@Qualifier("taraRestOperations") RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    public ClientRegistration createClientRegistration(String registrationId, TaraProperties properties) {
        String issuer = requireNonNull(properties.issuerUri());
        OIDCProviderMetadata metadata = getMetadata(issuer, restOperations);
        return ClientRegistration.withRegistrationId(registrationId)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                /* While we override scopes for each authorization request in `TaraAuthorizationRequestResolver`,
                 * `openid` scope needs to be defined here for spring to generate a nonce. */
                .scope(OidcScopes.OPENID)
                .authorizationUri(requireNonNull(metadata.getAuthorizationEndpointURI()).toASCIIString())
                .tokenUri(requireNonNull(metadata.getTokenEndpointURI()).toASCIIString())
                .jwkSetUri(requireNonNull(metadata.getJWKSetURI()).toASCIIString())
                .providerConfigurationMetadata(metadata.toJSONObject())
                .issuerUri(issuer)
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret())
                .redirectUri(properties.redirectUri())
                .build();
    }

    private OIDCProviderMetadata getMetadata(String issuer, RestOperations taraRestOperations) {
        URI issuerUri = URI.create(issuer);
        URI metadataUri = UriComponentsBuilder.fromUri(issuerUri)
                .replacePath(issuerUri.getPath() + OIDC_METADATA_PATH)
                .build(Collections.emptyMap());
        RequestEntity<Void> request = RequestEntity.get(metadataUri).build();
        JSONObject configuration = requireNonNull(taraRestOperations.exchange(request, JSONObject.class).getBody());
        OIDCProviderMetadata metadata = parseMetadata(configuration);
        verifyIssuer(issuer, metadata);
        return metadata;
    }

    private static OIDCProviderMetadata parseMetadata(JSONObject configuration) {
        try {
            return OIDCProviderMetadata.parse(configuration);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private static void verifyIssuer(String issuer, OIDCProviderMetadata metadata) {
        String metadataIssuer = metadata.getIssuer().getValue();
        if (!Objects.equals(issuer, metadataIssuer)) {
            throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided " +
                    "in the configuration metadata did not match the requested issuer \"" + issuer + "\"");
        }
    }

}
