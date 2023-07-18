package ee.ria.govsso.client.govsso.oauth2;

import lombok.experimental.UtilityClass;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Duration;
import java.time.Instant;

@UtilityClass
public class GovssoSessionUtil {

    public Duration getTimeUntilAuthenticationExpiration() {
        return Duration.between(Instant.now(), getOidcAuthenticationExpiration());
    }

    private Instant getOidcAuthenticationExpiration() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ((OidcUser) authentication.getPrincipal()).getExpiresAt();
    }
}
