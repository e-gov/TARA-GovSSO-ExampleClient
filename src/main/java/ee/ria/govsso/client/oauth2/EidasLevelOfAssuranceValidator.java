package ee.ria.govsso.client.oauth2;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.EnumUtils;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class EidasLevelOfAssuranceValidator implements OAuth2TokenValidator<Jwt> {

    private final EidasLevelOfAssurance minimumEidasLevelOfAssurance;
    private final EidasLevelOfAssuranceValidationResultFactory validationResultFactory;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String levelOfAssuranceString = token.getClaimAsString(IdTokenClaimNames.ACR);
        if (levelOfAssuranceString == null) {
            return validationResultFactory.invalidAcrValue();
        }
        if (!EnumUtils.isValidEnumIgnoreCase(EidasLevelOfAssurance.class, levelOfAssuranceString)) {
            return validationResultFactory.invalidAcrValue();
        }
        if (!EidasLevelOfAssurance.fromValue(levelOfAssuranceString).isAtLeast(minimumEidasLevelOfAssurance)) {
            return validationResultFactory.insufficientAcrValue(minimumEidasLevelOfAssurance);
        }
        return validationResultFactory.success();
    }

}
