package ee.ria.govsso.client.controller;

import ee.ria.govsso.client.authentication.ExampleClientUser;
import ee.ria.govsso.client.configuration.ExampleClientSessionProperties;
import ee.ria.govsso.client.govsso.configuration.authentication.GovssoAuthentication;
import ee.ria.govsso.client.govsso.oauth2.GovssoSessionUtil;
import ee.ria.govsso.client.util.AccessTokenUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import static ee.ria.govsso.client.govsso.configuration.condition.OnGovssoCondition.GOVSSO_PROFILE;
import static ee.ria.govsso.client.tara.configuration.condition.OnTaraCondition.TARA_PROFILE;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientController {
    public static final String LOGIN_VIEW_MAPPING = "/";
    public static final String DASHBOARD_MAPPING = "/dashboard";

    private final ExampleClientSessionProperties sessionProperties;
    private final Environment environment;

    @Value("${example-client.logo}")
    private String applicationLogo;
    @Value("${example-client.messages.title}")
    private String applicationTitle;
    @Value("${example-client.messages.intro-long}")
    private String applicationIntroLong;
    @Value("${example-client.messages.info-service}")
    private String applicationInfoService;

    @GetMapping(value = LOGIN_VIEW_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView clientLoginView(
            @AuthenticationPrincipal OidcUser oidcUser,
            @RequestParam(name = "show-post-logout-message", required = false) String showPostLogoutMessage) {
        if (oidcUser == null) {
            log.info("Unauthenticated user detected. Showing index page.");
            ModelAndView model = new ModelAndView("loginView");

            model.addObject("application_title", applicationTitle);
            model.addObject("application_intro_long", applicationIntroLong);
            model.addObject("application_info_service", applicationInfoService);
            model.addObject("application_logo", applicationLogo);
            model.addObject("authentication_provider", getAuthenticationProvider());
            model.addObject("show_post_logout_message", showPostLogoutMessage != null);
            return model;
        } else {
            log.info("User has been authenticated, redirecting browser to dashboard. subject='{}'", oidcUser.getSubject());
            return new ModelAndView("redirect:/dashboard");
        }
    }

    @GetMapping(value = DASHBOARD_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView dashboard(@AuthenticationPrincipal OidcUser oidcUser, ExampleClientUser exampleClientUser, GovssoAuthentication authentication) {
        ModelAndView model = new ModelAndView("dashboard");
        model.addObject("application_logo", applicationLogo);
        model.addObject("authentication_provider", getAuthenticationProvider());
        model.addObject("application_title", applicationTitle);
        model.addObject("exampleClientUser", exampleClientUser);
        model.addObject("allowed_idle_time", sessionProperties.idleTimeout().toSeconds());
        model.addObject("refresh_token", authentication.getRefreshToken().getTokenValue());
        String accessToken = authentication.getAccessToken().getTokenValue();
        if (AccessTokenUtil.isJwtAccessToken(accessToken)) {
            model.addObject("access_token", accessToken);
        }

        log.info("Showing dashboard for subject='{}'", oidcUser.getSubject());
        addIdTokenDataToModel(oidcUser, model);

        return model;
    }

    private void addIdTokenDataToModel(OidcUser oidcUser, ModelAndView model) {
        model.addObject("id_token", oidcUser.getIdToken().getTokenValue());
        model.addObject("claims", flattenClaims(oidcUser.getClaims()).entrySet());
        model.addObject(
                "time_until_govsso_session_expiration_in_seconds",
                GovssoSessionUtil.getTimeUntilAuthenticationExpiration().toSeconds());
    }

    private Map<String, String> flattenClaims(Map<?, ?> claims) {
        SortedMap<String, String> flatClaims = new TreeMap<>();
        for (Map.Entry<?, ?> claim : claims.entrySet()) {
            String key = claim.getKey().toString();
            Object value = claim.getValue();
            if (value instanceof Map<?, ?> innerClaims) {
                Map<String, String> flattenedInnerClaims = flattenClaims(innerClaims);
                for (Map.Entry<String, String> innerClaim : flattenedInnerClaims.entrySet()) {
                    flatClaims.put(key + "." + innerClaim.getKey(), innerClaim.getValue());
                }
                continue;
            }
            flatClaims.put(key, renderClaimValue(value));
        }
        return flatClaims;
    }

    private static String renderClaimValue(Object value) {
        if (value instanceof Date date) {
            return date.toInstant().toString();
        }
        return value.toString();
    }

    private String getAuthenticationProvider() {
        Set<String> authenticationProviderProfiles = Set.of(GOVSSO_PROFILE, TARA_PROFILE);
        Set<String> activeProfiles = Set.of(environment.getActiveProfiles());
        return authenticationProviderProfiles.stream()
                .filter(activeProfiles::contains)
                .findAny()
                .orElseThrow();
    }

}
