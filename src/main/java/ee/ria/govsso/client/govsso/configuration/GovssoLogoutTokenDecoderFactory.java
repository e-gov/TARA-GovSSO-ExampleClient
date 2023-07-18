package ee.ria.govsso.client.govsso.configuration;

import ee.ria.govsso.client.oauth2.OidcLogoutTokenValidator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import static ee.ria.govsso.client.govsso.configuration.GovssoOidcConfiguration.GOVSSO_REGISTRATION_ID;
import static org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters;

/* Since `org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer`
 * will break if there are multiple beans of type `JwtDecoderFactory<ClientRegistration>` present, we will not
 * be registering this class as a bean.
 */
public class GovssoLogoutTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.RS256;

    private final RestOperations restOperations;
    private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

    public GovssoLogoutTokenDecoderFactory(@Qualifier("govssoRestOperations") RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        if (!Objects.equals(clientRegistration.getRegistrationId(), GOVSSO_REGISTRATION_ID)) {
            throw new IllegalArgumentException(
                    GovssoIdTokenDecoderFactory.class.getName() + " only supports GovSSO");
        }
        return jwtDecoders.computeIfAbsent(
                clientRegistration.getRegistrationId(),
                registrationId -> doCreateDecoder(clientRegistration));
    }

    private NimbusJwtDecoder doCreateDecoder(ClientRegistration clientRegistration) {
        String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SIGNATURE_ALGORITHM)
                .restOperations(restOperations)
                .build();
        jwtDecoder.setJwtValidator(new OidcLogoutTokenValidator(clientRegistration));
        jwtDecoder.setClaimSetConverter(new ClaimTypeConverter(createDefaultClaimTypeConverters()));
        return jwtDecoder;
    }

}
