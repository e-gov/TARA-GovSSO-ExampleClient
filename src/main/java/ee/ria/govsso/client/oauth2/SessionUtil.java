package ee.ria.govsso.client.oauth2;

import lombok.experimental.UtilityClass;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;

@UtilityClass
public class SessionUtil {

    public long getTimeUntilAuthenticationExpirationInSeconds() {
        Instant instant = getOidcAuthenticationExpiration();
        return instant.getEpochSecond() - Instant.now().getEpochSecond();
    }

    private Instant getOidcAuthenticationExpiration() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ((OidcUser) authentication.getPrincipal()).getExpiresAt();
    }
}
