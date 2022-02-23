package ee.ria.govsso.client.ouath2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomRegisterSessionAuthenticationStrategy extends RegisterSessionAuthenticationStrategy {
    public CustomRegisterSessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
        super(sessionRegistry);
    }

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        // Should not create new application session during GOVSSO session update process.
        if (!AuthenticationUtil.sessionMatchesWithExistingAuthToken(authentication)) {
            super.onAuthentication(authentication, request, response);
        }
    }
}
