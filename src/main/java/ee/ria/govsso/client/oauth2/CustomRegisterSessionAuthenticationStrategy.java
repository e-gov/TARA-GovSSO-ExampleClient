package ee.ria.govsso.client.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;

public class CustomRegisterSessionAuthenticationStrategy extends RegisterSessionAuthenticationStrategy {
    public CustomRegisterSessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
        super(sessionRegistry);
    }

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        // Should not create new application session during GovSSO session update process.
        if (!AuthenticationUtil.sessionMatchesWithExistingAuthToken(authentication)) {
            super.onAuthentication(authentication, request, response);
        }
    }
}
