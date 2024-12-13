package ee.ria.govsso.client.govsso.oauth2;

import ee.ria.govsso.client.util.LogoutUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static ee.ria.govsso.client.govsso.oauth2.GovssoLocalePassingLogoutHandler.UI_LOCALES_PARAMETER;

/**
 * A custom logout success handler for initiating OIDC logout with additional ui_locales parameter.
 *
 * @see org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
 */
public class GovssoClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final String postLogoutRedirectUri;
    private final DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public GovssoClientInitiatedLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.redirectStrategy.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        handle(request, response, authentication);
    }

    @Override
    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        if (response.isCommitted()) {
            this.logger.debug(LogMessage.format("Did not redirect to %s since response already committed.", targetUrl));
            return;
        }

        this.redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String targetUrl = null;
        if (authentication instanceof OAuth2AuthenticationToken authToken && authentication.getPrincipal() instanceof OidcUser) {
            String registrationId = authToken.getAuthorizedClientRegistrationId();
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
            URI endSessionEndpoint = endSessionEndpoint(clientRegistration);
            if (endSessionEndpoint != null) {
                String idToken = idToken(authentication);
                String postLogoutRedirectUri = LogoutUtil.postLogoutRedirectUri(request, this.postLogoutRedirectUri);
                targetUrl = endpointUri(request, endSessionEndpoint, idToken, postLogoutRedirectUri);
            }
        }
        return (targetUrl != null) ? targetUrl : super.determineTargetUrl(request, response);
    }

    private URI endSessionEndpoint(ClientRegistration clientRegistration) {
        if (clientRegistration != null) {
            ClientRegistration.ProviderDetails providerDetails = clientRegistration.getProviderDetails();
            Object endSessionEndpoint = providerDetails.getConfigurationMetadata().get("end_session_endpoint");
            if (endSessionEndpoint != null) {
                return URI.create(endSessionEndpoint.toString());
            }
        }
        return null;
    }

    private String idToken(Authentication authentication) {
        return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
    }

    private String endpointUri(HttpServletRequest request, URI endSessionEndpoint, String idToken, String postLogoutRedirectUri) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);

        String locale = (String) request.getAttribute(UI_LOCALES_PARAMETER);

        if (request.getMethod().equals(HttpMethod.GET.name())) {
            builder.queryParam("id_token_hint", idToken);
            if (StringUtils.isNotEmpty(locale)) {
                builder.queryParam(UI_LOCALES_PARAMETER, locale);
            }
        }
        if (postLogoutRedirectUri != null) {
            builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
        }

        return builder.encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();
    }
}
