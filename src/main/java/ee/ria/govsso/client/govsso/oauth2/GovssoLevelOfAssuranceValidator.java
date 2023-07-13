package ee.ria.govsso.client.govsso.oauth2;

import org.apache.commons.lang3.EnumUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

import static com.nimbusds.openid.connect.sdk.assurance.IdentityAssuranceLevel.SUBSTANTIAL;

public class GovssoLevelOfAssuranceValidator implements OAuth2TokenValidator<Jwt> {

    private static OAuth2TokenValidatorResult insufficientAcrValue() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_id_token",
                "The ID Token contains insufficient `acr` (eIDAS level of assurance) value, expected at least '%s'"
                        .formatted(SUBSTANTIAL.getValue()), null));
    }

    private static OAuth2TokenValidatorResult invalidAcrValue() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_id_token",
                "The ID Token contains invalid `acr` (eIDAS level of assurance) value",
                "https://e-gov.github.io/GOVSSO/TechnicalSpecification#71-verification-of-the-id-token-and-logout-token"));
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String levelOfAssuranceString = token.getClaimAsString(IdTokenClaimNames.ACR);
        if (levelOfAssuranceString == null) {
            return invalidAcrValue();
        }
        if (!EnumUtils.isValidEnumIgnoreCase(EidasLevelOfAssurance.class, levelOfAssuranceString)) {
            return invalidAcrValue();
        }
        if (!EidasLevelOfAssurance.fromValue(levelOfAssuranceString).isAtLeast(EidasLevelOfAssurance.SUBSTANTIAL)) {
            return insufficientAcrValue();
        }
        return OAuth2TokenValidatorResult.success();
    }

    enum EidasLevelOfAssurance implements Comparable<EidasLevelOfAssurance> {
        LOW, SUBSTANTIAL, HIGH;

        public static EidasLevelOfAssurance fromValue(String value) {
            return EidasLevelOfAssurance.valueOf(value.toUpperCase());
        }

        public boolean isAtLeast(EidasLevelOfAssurance minimumLevel) {
            return compareTo(minimumLevel) >= 0;
        }
    }
}
