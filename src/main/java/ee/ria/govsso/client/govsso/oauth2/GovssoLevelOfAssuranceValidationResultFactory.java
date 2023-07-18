package ee.ria.govsso.client.govsso.oauth2;

import ee.ria.govsso.client.govsso.configuration.condition.ConditionalOnGovsso;
import ee.ria.govsso.client.oauth2.EidasLevelOfAssurance;
import ee.ria.govsso.client.oauth2.EidasLevelOfAssuranceValidationResultFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnGovsso
public class GovssoLevelOfAssuranceValidationResultFactory implements EidasLevelOfAssuranceValidationResultFactory {

    @Override
    public OAuth2TokenValidatorResult insufficientAcrValue(EidasLevelOfAssurance minimumEidasLevelOfAssurance) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_id_token",
                "The ID Token contains insufficient `acr` (eIDAS level of assurance) value, expected at least '%s'"
                        .formatted(minimumEidasLevelOfAssurance), null));
    }

    @Override
    public OAuth2TokenValidatorResult invalidAcrValue() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_id_token",
                "The ID Token contains invalid `acr` (eIDAS level of assurance) value",
                "https://e-gov.github.io/GOVSSO/TechnicalSpecification#71-verification-of-the-id-token-and-logout-token"));
    }

    @Override
    public OAuth2TokenValidatorResult success() {
        return OAuth2TokenValidatorResult.success();
    }
}
