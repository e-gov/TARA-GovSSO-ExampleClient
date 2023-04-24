package ee.ria.govsso.client.controller;

import ee.ria.govsso.client.authentication.ExampleClientUser;
import ee.ria.govsso.client.configuration.ExampleClientSessionProperties;
import ee.ria.govsso.client.oauth2.SessionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientController {
    public static final String LOGIN_VIEW_MAPPING = "/";
    public static final String DASHBOARD_MAPPING = "/dashboard";

    private final ExampleClientSessionProperties sessionProperties;

    @Value("${spring.application.name}")
    private String applicationName;
    @Value("${example-client.logo}")
    private String applicationLogo;

    @GetMapping(value = LOGIN_VIEW_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView clientLoginView(@AuthenticationPrincipal OidcUser oidcUser) {
        if (oidcUser == null) {
            log.info("Unauthenticated user detected. Showing index page.");
            ModelAndView model = new ModelAndView("loginView");
            model.addObject("application_name", applicationName);
            model.addObject("application_logo", applicationLogo);
            return model;
        } else {
            log.info("User has been authenticated by GovSSO, redirecting browser to dashboard. subject='{}'", oidcUser.getSubject());
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

        log.info("Showing dashboard for subject='{}'", oidcUser.getSubject());
        addIdTokenDataToModel(oidcUser, model);

        return model;
    }

    private void addIdTokenDataToModel(OidcUser oidcUser, ModelAndView model) {
        model.addObject("id_token", oidcUser.getIdToken().getTokenValue());
        model.addObject("jti", oidcUser.getClaimAsString("jti"));
        model.addObject("iss", oidcUser.getIssuer());
        model.addObject("aud", oidcUser.getAudience());
        model.addObject("exp", oidcUser.getExpiresAt());
        model.addObject("iat", oidcUser.getIssuedAt());
        model.addObject("sub", oidcUser.getSubject());
        model.addObject("birthdate", oidcUser.getClaimAsString("birthdate"));
        model.addObject("given_name", oidcUser.getClaimAsString("given_name"));
        model.addObject("family_name", oidcUser.getClaimAsString("family_name"));
        if (oidcUser.hasClaim("phone_number")) {
            model.addObject("phone_number", oidcUser.getPhoneNumber());
        }
        if (oidcUser.hasClaim("phone_number_verified")) {
            model.addObject("phone_number_verified", oidcUser.getPhoneNumberVerified());
        }
        model.addObject("amr", oidcUser.getAuthenticationMethods());
        model.addObject("nonce", oidcUser.getNonce());
        model.addObject("acr", oidcUser.getAuthenticationContextClass());
        model.addObject("at_hash", oidcUser.getAccessTokenHash());
        model.addObject("sid", oidcUser.getIdToken().getClaim("sid"));
        model.addObject("time_until_govsso_session_expiration_in_seconds", SessionUtil.getTimeUntilAuthenticationExpirationInSeconds());

    }
}
