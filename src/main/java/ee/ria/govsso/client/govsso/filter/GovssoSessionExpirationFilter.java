package ee.ria.govsso.client.govsso.filter;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;

@Slf4j
@RequiredArgsConstructor
@Builder
public class GovssoSessionExpirationFilter extends OncePerRequestFilter {

    private final Clock clock;
    private final SessionRegistry sessionRegistry;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (isOidcAuthenticationExpired()) {
            log.info("OIDC authentication expired, marking session as expired");
            HttpSession session = request.getSession(false);
            this.sessionRegistry.getSessionInformation(session.getId()).expireNow();
        }
        filterChain.doFilter(request, response);
    }

    private boolean isOidcAuthenticationExpired() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        if (!(authentication instanceof OAuth2AuthenticationToken oAuth2Authentication)) {
            return false;
        }
        Instant authenticationExpiration = ((OidcUser) oAuth2Authentication.getPrincipal()).getExpiresAt();
        return authenticationExpiration.isBefore(clock.instant());
    }

}
