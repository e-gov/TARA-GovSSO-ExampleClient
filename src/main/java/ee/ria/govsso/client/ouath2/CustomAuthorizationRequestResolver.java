package ee.ria.govsso.client.ouath2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.thymeleaf.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.LinkedHashMap;
import java.util.Map;

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private final OAuth2AuthorizationRequestResolver requestResolver;
    private final SessionRegistry sessionRegistry;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, SessionRegistry sessionRegistry) {
        this.requestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest httpServletRequest) {
        OAuth2AuthorizationRequest authorizationRequest = requestResolver.resolve(httpServletRequest);
        if (authorizationRequest == null) {
            return null;
        }
        return customAuthorizationRequest(authorizationRequest, httpServletRequest);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest httpServletRequest, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = requestResolver.resolve(httpServletRequest, clientRegistrationId);
        if (authorizationRequest == null) {
            return null;
        }
        return customAuthorizationRequest(authorizationRequest, httpServletRequest);
    }

    private OAuth2AuthorizationRequest customAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest httpServletRequest) {
        Map<String, Object> additionalParameters = new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());

        if (isUpdateRequest(httpServletRequest)) {
            checkSessionExpiration(httpServletRequest.getSession());
            additionalParameters.put("id_token_hint", getPreviousIdToken());
            additionalParameters.put("prompt", "none");
        }

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .build();
    }

    private boolean isUpdateRequest(HttpServletRequest httpServletRequest) {
        return StringUtils.equalsIgnoreCase(httpServletRequest.getParameter("prompt"), "none");
    }

    private String getPreviousIdToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            throw new RuntimeException("Invalid token update request. Previous authentication was not done through OIDC.");
        }
        OidcUser user = (OidcUser) authentication.getPrincipal();
        if (StringUtils.isEmpty(user.getIdToken().getTokenValue())) {
            throw new RuntimeException("Invalid token update request. Previous ID token not found in session.");
        }

        return user.getIdToken().getTokenValue();
    }

    private void checkSessionExpiration(HttpSession httpSession) {
        if (httpSession == null) {
            throw new SessionAuthenticationException("HttpSession not found or invalid session");
        }
        SessionInformation sessionInformation = sessionRegistry.getSessionInformation(httpSession.getId());
        if (sessionInformation == null || sessionInformation.isExpired()) {
            throw new SessionAuthenticationException("HttpSession has already expired. Can not continue with OIDC authentication.");
        }
    }

}
