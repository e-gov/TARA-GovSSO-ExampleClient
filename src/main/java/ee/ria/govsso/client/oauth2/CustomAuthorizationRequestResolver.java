package ee.ria.govsso.client.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.thymeleaf.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import static ee.ria.govsso.client.oauth2.LocalePassingLogoutHandler.UI_LOCALES_PARAMETER;
import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

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

        String locale = httpServletRequest.getParameter("locale");
        String acr = httpServletRequest.getParameter("acr");

        /*
            OAuth2AuthorizationRequestRedirectFilter will create new session right after resolving
            authorization request, so it's ok to create it here also.
        */
        HttpSession session = httpServletRequest.getSession();
        if (locale != null) {
            additionalParameters.put(UI_LOCALES_PARAMETER, locale);
            /*
                Using LOCALE_SESSION_ATTRIBUTE_NAME to store selected locale is compatible with
                Spring SessionLocaleResolver/LocaleChangeInterceptor. You cannot use LocaleChangeInterceptor alone
                to store selected authentication locale, because OAuth2AuthorizationRequestRedirectFilter performs
                redirect before LocaleChangeInterceptor has an opportunity to detect locale change.
             */
            session.setAttribute(LOCALE_SESSION_ATTRIBUTE_NAME, new Locale(locale));
        }
        if (acr != null) {
            additionalParameters.put("acr_values", acr);
        }

        if (isUpdateRequest(httpServletRequest)) {
            checkSessionExpiration(session);
            OidcIdToken previousIdToken = getPreviousIdToken();
            additionalParameters.put("id_token_hint", previousIdToken.getTokenValue());
            additionalParameters.put("prompt", "none");
            additionalParameters.computeIfAbsent("acr_values", v -> previousIdToken.getClaim("acr"));
        }

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .build();
    }

    private boolean isUpdateRequest(HttpServletRequest httpServletRequest) {
        return StringUtils.equalsIgnoreCase(httpServletRequest.getParameter("prompt"), "none");
    }

    private OidcIdToken getPreviousIdToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            throw new RuntimeException("Invalid token update request. Previous authentication was not done through OIDC.");
        }
        OidcUser user = (OidcUser) authentication.getPrincipal();
        if (StringUtils.isEmpty(user.getIdToken().getTokenValue())) {
            throw new RuntimeException("Invalid token update request. Previous ID token not found in session.");
        }

        return user.getIdToken();
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
