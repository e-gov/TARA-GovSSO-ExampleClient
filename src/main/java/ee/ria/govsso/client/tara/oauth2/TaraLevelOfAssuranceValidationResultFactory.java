package ee.ria.govsso.client.tara.oauth2;

import ee.ria.govsso.client.oauth2.EidasLevelOfAssurance;
import ee.ria.govsso.client.oauth2.EidasLevelOfAssuranceValidationResultFactory;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnTara
public class TaraLevelOfAssuranceValidationResultFactory implements EidasLevelOfAssuranceValidationResultFactory {

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
                "https://e-gov.github.io/TARA-Doku/TechnicalSpecification#517-verifying-the-eidas-level-of-assurance"));
    }

    @Override
    public OAuth2TokenValidatorResult success() {
        return OAuth2TokenValidatorResult.success();
    }
}
