package ee.ria.govsso.client.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@RequiredArgsConstructor
public class CustomCsrfAuthenticationStrategy implements SessionAuthenticationStrategy {

    private final CsrfTokenRepository csrfTokenRepository;

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        // Should not replace CSRF token during GovSSO session update process.
        if (!AuthenticationUtil.sessionMatchesWithExistingAuthToken(authentication)) {
            replaceCsrfToken(request, response);
        }
    }

    // Code from org.springframework.security.web.csrf.CsrfAuthenticationStrategy, since class is final thus not extendable.
    public void replaceCsrfToken(HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        boolean containsToken = this.csrfTokenRepository.loadToken(request) != null;
        if (containsToken) {
            this.csrfTokenRepository.saveToken(null, request, response);
            CsrfToken newToken = this.csrfTokenRepository.generateToken(request);
            this.csrfTokenRepository.saveToken(newToken, request, response);
            request.setAttribute(CsrfToken.class.getName(), newToken);
            request.setAttribute(newToken.getParameterName(), newToken);
        }
    }
}
