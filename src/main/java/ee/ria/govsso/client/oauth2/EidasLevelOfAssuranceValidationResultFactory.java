package ee.ria.govsso.client.oauth2;

import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

public interface EidasLevelOfAssuranceValidationResultFactory {

    OAuth2TokenValidatorResult insufficientAcrValue(EidasLevelOfAssurance minimumEidasLevelOfAssurance);

    OAuth2TokenValidatorResult invalidAcrValue();

    OAuth2TokenValidatorResult success();

}
