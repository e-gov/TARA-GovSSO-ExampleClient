package ee.ria.govsso.client.tara.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static ee.ria.govsso.client.govsso.oauth2.GovssoLocalePassingLogoutHandler.UI_LOCALES_PARAMETER;
import static ee.ria.govsso.client.tara.configuration.TaraOidcConfiguration.TARA_REGISTRATION_ID;
import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

public class TaraAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver requestResolver;

    public TaraAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        this.requestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
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
        if (!Objects.equals(clientRegistrationId, TARA_REGISTRATION_ID)) {
            throw new IllegalArgumentException(
                    TaraAuthorizationRequestResolver.class.getName() + " only supports TARA");
        }
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
        String scopeParam = httpServletRequest.getParameter("scope");

        /*
            OAuth2AuthorizationRequestRedirectFilter will create new session right after resolving
            authorization request, so it's ok to create it here also.
        */
        HttpSession session = httpServletRequest.getSession();
        httpServletRequest.changeSessionId();
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

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .scopes(createScopesSet(authorizationRequest.getScopes(), scopeParam))
                .build();
    }

    private Set<String> createScopesSet(Set<String> originalScopes, String additionalScope) {
        Set<String> scopes = new HashSet<>(originalScopes);
        if (additionalScope != null) {
            scopes.add(additionalScope);
        }
        return scopes;
    }
}
