package ee.ria.govsso.client.govsso.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.util.StringUtils;

import java.io.IOException;
import java.util.List;

import static ee.ria.govsso.client.oauth2.OidcLogoutTokenValidator.SESSION_ID_CLAIM;
import static org.springframework.http.HttpMethod.POST;

/**
 * An {@link OidcBackChannelLogoutFilter} responsible for initiating back-channel logout.
 *
 * @implNote This implementation should be replaced by
 * <a target="_blank" href="https://github.com/spring-projects/spring-security/issues/7845">Support OpenID Connect Back-Channel Logout</a>.
 * Related pull request <a href="https://github.com/spring-projects/spring-security/pull/12570">#12570</a>.
 * Expected client back-channel logout URL format is {baseUrl}/oauth2/{registrationId}/logout
 * The registrationId is a unique identifier for the {@link  org.springframework.security.oauth2.client.registration.ClientRegistration}
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel">Back-Channel Logout</a>
 */
@Slf4j
@Builder
@RequiredArgsConstructor
public class OidcBackChannelLogoutFilter extends OncePerRequestFilter {

    public static final RequestMatcher REQUEST_MATCHER =
            new AntPathRequestMatcher("/oauth2/back-channel-logout/{registrationId}", POST.name());

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory;
    private final SessionRegistry sessionRegistry;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        RequestMatcher.MatchResult result = REQUEST_MATCHER.matcher(request);
        if (!result.isMatch()) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            handleBackChannelLogout(request, response, result);
        } catch (Exception e) {
            log.error("Failed to process back-channel logout request", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    private void handleBackChannelLogout(
            HttpServletRequest request, HttpServletResponse response, RequestMatcher.MatchResult result) {
        log.trace("Received back-channel logout request");
        String registrationId = result.getVariables().get("registrationId");
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new RuntimeException("No client registration found: registration_id='" + registrationId + "'");
        }
        log.trace("Matching client registration found: {}", clientRegistration);
        String logoutToken = request.getParameter("logout_token");
        if (logoutToken == null) {
            throw new RuntimeException("No logout token provided");
        }
        log.debug("Received back-channel logout request token: {}", logoutToken);
        Jwt validLogoutToken = logoutTokenDecoderFactory.createDecoder(clientRegistration).decode(logoutToken);
        invalidateOidcUserSession(validLogoutToken);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    private void invalidateOidcUserSession(Jwt logoutToken) {
        String govssoSid = logoutToken.getClaimAsString(SESSION_ID_CLAIM);
        List<SessionInformation> sessions = sessionRegistry.getAllPrincipals()
                .stream()
                .filter(principal -> principal instanceof DefaultOidcUser defaultOidcUser &&
                        StringUtils.equals(defaultOidcUser.getClaim("sid"), govssoSid))
                .map(DefaultOidcUser.class::cast)
                .flatMap(oidcUser -> sessionRegistry.getAllSessions(oidcUser, false).stream())
                .toList();
        if (sessions.isEmpty()) {
            log.info("No session found, govsso-sid='" + govssoSid + "'");
            return;
        }
        sessions.forEach(session -> {
            String subject = ((DefaultOidcUser) session.getPrincipal()).getSubject();
            log.info("Terminating session govsso-sid='{}', session-id='{}', sub='{}'",
                    govssoSid, session.getSessionId(), subject);
            session.expireNow();
        });
    }
}
