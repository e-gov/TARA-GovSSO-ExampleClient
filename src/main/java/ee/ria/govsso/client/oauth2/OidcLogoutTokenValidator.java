package ee.ria.govsso.client.oauth2;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link OidcLogoutTokenValidator} responsible for validating the claims in Logout Token.
 * <p>
 * Roughly based on {@link org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator}
 *
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation">Logout Token Validation</a>
 */
@RequiredArgsConstructor
public class OidcLogoutTokenValidator implements OAuth2TokenValidator<Jwt> {
    public static final String SESSION_ID_CLAIM = "sid";
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);
    private static final String EVENTS_CLAIM = "events";
    private static final String BACK_CHANNEL_LOGOUT_MEMBER_NAME = "http://schemas.openid.net/event/backchannel-logout";
    private final ClientRegistration clientRegistration;
    private final Clock clock = Clock.systemUTC();

    private static OAuth2Error invalidLogoutToken(Map<String, Object> invalidClaims) {
        return new OAuth2Error("invalid_logout_token", "The Logout Token contains invalid claims: " + invalidClaims,
                "https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.6");
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt logoutToken) {
        // 2.6 Logout Token Validation
        Map<String, Object> invalidClaims = new HashMap<>();
        // > 1 If the Logout Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration.
        // > GovSSO does not encrypt the Logout Token.

        // > 2 Validate the Logout Token signature
        // > Validated at this point

        // > 3 Validate the alg (algorithm) Header Parameter in the same way it is validated for ID Tokens.
        // > Validated at this point

        // > 4. Validate the `iss`, `aud`, and `iat` Claims in the same way they are validated in ID Tokens.
        String metadataIssuer = clientRegistration.getProviderDetails().getIssuerUri();
        URL issClaim = logoutToken.getIssuer();
        if (metadataIssuer == null || issClaim == null || !metadataIssuer.equals(issClaim.toExternalForm())) {
            invalidClaims.put(IdTokenClaimNames.ISS, issClaim);
        }
        List<String> audClaim = logoutToken.getAudience();
        if (audClaim == null || !audClaim.contains(clientRegistration.getClientId())) {
            invalidClaims.put(IdTokenClaimNames.AUD, StringUtils.join(audClaim));
        }
        Instant iatClaim = logoutToken.getIssuedAt();
        Instant now = Instant.now(this.clock);
        if (iatClaim == null || now.plus(CLOCK_SKEW).isBefore(iatClaim)) {
            invalidClaims.put(IdTokenClaimNames.IAT, iatClaim);
        }

        // > 5. Verify that the Logout Token contains a `sub` Claim, a `sid` Claim, or both.
        // > GovSSO only uses `sid` claim.
        if (StringUtils.isBlank(logoutToken.getClaim(SESSION_ID_CLAIM))) {
            invalidClaims.put(SESSION_ID_CLAIM, null);
        }

        // > 6. Verify that the Logout Token contains an `events` Claim whose value is JSON object containing
        // > the member name http://schemas.openid.net/event/backchannel-logout.
        Map<String, Object> eventsClaim = logoutToken.getClaimAsMap(EVENTS_CLAIM);
        if (eventsClaim == null || !eventsClaim.containsKey(BACK_CHANNEL_LOGOUT_MEMBER_NAME)) {
            invalidClaims.put(EVENTS_CLAIM, StringUtils.join(eventsClaim));
        }

        // > 7. Verify that the Logout Token does not contain a `nonce` Claim.
        String nonceClaim = logoutToken.getClaimAsString(IdTokenClaimNames.NONCE);
        if (!StringUtils.isBlank(nonceClaim)) {
            invalidClaims.put(IdTokenClaimNames.NONCE, nonceClaim);
        }

        if (!invalidClaims.isEmpty()) {
            return OAuth2TokenValidatorResult.failure(invalidLogoutToken(invalidClaims));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
