package ee.ria.govsso.client.configuration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.time.Clock;
import java.time.Instant;

import static ee.ria.govsso.client.filter.ExampleClientSessionExpirationFilter.SESSION_EXPIRATION_TIME_ATTR;

@RequiredArgsConstructor
public class ExampleClientSessionExpirationAuthenticationStrategy implements SessionAuthenticationStrategy {

    private final ExampleClientSessionProperties properties;
    private final Clock clock;

    @Override
    public void onAuthentication(
            Authentication authentication, HttpServletRequest request, HttpServletResponse response)
            throws SessionAuthenticationException {
        request.getSession().setAttribute(
                SESSION_EXPIRATION_TIME_ATTR,
                Instant.now(clock).plus(properties.idleTimeout()));
    }

}
