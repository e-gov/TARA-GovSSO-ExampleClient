package ee.ria.govsso.client.filter;

import ee.ria.govsso.client.configuration.ExampleClientSessionProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static java.time.temporal.ChronoUnit.SECONDS;

@Slf4j
@RequiredArgsConstructor
@Builder
public class ExampleClientSessionExpirationFilter extends OncePerRequestFilter {

    public static final String SESSION_EXPIRATION_TIME_ATTR =
            ExampleClientSessionExpirationFilter.class.getName() + ".SESSION_EXPIRATION_TIME";
    private static final Duration ALLOWED_SKEW = Duration.of(10, SECONDS);

    private final Clock clock;
    private final ExampleClientSessionProperties sessionProperties;
    private final SessionRegistry sessionRegistry;

    private final RequestMatcher userActivity = new NegatedRequestMatcher(new AntPathRequestMatcher("/oauth2/**"));

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        handleSession(request);
        filterChain.doFilter(request, response);
    }

    private void handleSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.debug("Session not started, not extending local session");
            return;
        }
        SessionInformation sessionInformation = sessionRegistry.getSessionInformation(session.getId());
        if  (sessionInformation == null) {
            log.debug("Session exists but user not authenticated, removing local session timeout (if present)");
            clearSessionExpiration(session);
            return;
        }
        if (isExpired(session)) {
            log.info("Allowed idle time exceeded, expiring local session");
            clearSessionExpiration(session);
            sessionInformation.expireNow();
            return;
        }
        if (!userActivity.matches(request)) {
            log.debug("Request not considered user activity, not extending local session");
            return;
        }
        log.debug("Extending local session");
        updateSessionExpiration(session);
    }

    private boolean isExpired(HttpSession session) {
        Instant expirationTime = (Instant) session.getAttribute(SESSION_EXPIRATION_TIME_ATTR);
        if (expirationTime == null) {
            log.warn("Session expiration time not set");
            return false;
        }
        return Instant.now(clock).isAfter(expirationTime.plus(ALLOWED_SKEW));
    }

    private void updateSessionExpiration(HttpSession session) {
        session.setAttribute(SESSION_EXPIRATION_TIME_ATTR, Instant.now(clock).plus(sessionProperties.idleTimeout()));
    }

    private void clearSessionExpiration(HttpSession session) {
        session.removeAttribute(SESSION_EXPIRATION_TIME_ATTR);
    }

}
