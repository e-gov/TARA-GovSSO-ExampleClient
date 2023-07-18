package ee.ria.govsso.client.tara.configuration;

import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import ee.ria.govsso.client.tara.oauth2.TaraLevelOfAssuranceValidator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import static ee.ria.govsso.client.tara.configuration.TaraOidcConfiguration.TARA_REGISTRATION_ID;
import static org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters;

@Component
@Qualifier("idTokenDecoderFactory")
@ConditionalOnTara
public class TaraIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.RS256;

    private final RestOperations restOperations;
    private final TaraLevelOfAssuranceValidator taraLevelOfAssuranceValidator;
    private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

    public TaraIdTokenDecoderFactory(
            @Qualifier("taraRestOperations") RestOperations restOperations,
            TaraLevelOfAssuranceValidator taraLevelOfAssuranceValidator) {
        this.restOperations = restOperations;
        this.taraLevelOfAssuranceValidator = taraLevelOfAssuranceValidator;
    }

    @Override
    public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        if (!Objects.equals(clientRegistration.getRegistrationId(), TARA_REGISTRATION_ID)) {
            throw new IllegalArgumentException(
                    TaraIdTokenDecoderFactory.class.getName() + " only supports TARA");
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
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new OidcIdTokenValidator(clientRegistration),
                taraLevelOfAssuranceValidator
        ));
        jwtDecoder.setClaimSetConverter(new ClaimTypeConverter(createDefaultClaimTypeConverters()));
        return jwtDecoder;
    }

}
