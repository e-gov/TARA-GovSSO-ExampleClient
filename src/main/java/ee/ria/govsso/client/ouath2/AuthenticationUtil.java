package ee.ria.govsso.client.ouath2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.thymeleaf.util.StringUtils;

public class AuthenticationUtil {

    static boolean sessionMatchesWithExistingAuthToken(Authentication newAuthentication) {
        Authentication existingAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuthentication == null || !existingAuthentication.isAuthenticated()) {
            return false;
        }

        OAuth2User existingAuthPrincipal = ((OAuth2AuthenticationToken) existingAuthentication).getPrincipal();
        OAuth2User newAuthPrincipal = ((OAuth2AuthenticationToken) newAuthentication).getPrincipal();
        return StringUtils.equals(existingAuthPrincipal.getAttribute("sid"), newAuthPrincipal.getAttribute("sid")) &&
                StringUtils.equals(existingAuthPrincipal.getAttribute("sub"), newAuthPrincipal.getAttribute("sub"));
    }
}
