package ee.ria.govsso.client.controller;

import ee.ria.govsso.client.authentication.ExampleClientUser;
import ee.ria.govsso.client.configuration.ExampleClientSessionProperties;
import ee.ria.govsso.client.govsso.oauth2.GovssoSessionUtil;
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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

    @Value("${spring.application.name}")
    private String applicationName;
    @Value("${example-client.logo}")
    private String applicationLogo;

    @GetMapping(value = LOGIN_VIEW_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView clientLoginView(
            @AuthenticationPrincipal OidcUser oidcUser,
            @RequestParam(name = "show-post-logout-message", required = false) String showPostLogoutMessage) {
        if (oidcUser == null) {
            log.info("Unauthenticated user detected. Showing index page.");
            ModelAndView model = new ModelAndView("loginView");
            model.addObject("application_name", applicationName);
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
    public ModelAndView dashboard(@AuthenticationPrincipal OidcUser oidcUser, ExampleClientUser exampleClientUser) {
        ModelAndView model = new ModelAndView("dashboard");
        model.addObject("application_name", applicationName);
        model.addObject("application_logo", applicationLogo);

        model.addObject("exampleClientUser", exampleClientUser);
        model.addObject("allowed_idle_time", sessionProperties.idleTimeout().toSeconds());
        model.addObject("authentication_provider", getAuthenticationProvider());

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
        Map<String, String> flatClaims = new LinkedHashMap<>();
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
            flatClaims.put(key, value.toString());
        }
        return flatClaims;
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
