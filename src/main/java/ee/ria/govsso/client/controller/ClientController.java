package ee.ria.govsso.client.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.util.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientController {

    public static final String LOGIN_VIEW_MAPPING = "/";
    public static final String DASHBOARD_MAPPING = "/dashboard";
    public static final String BACKCHANNEL_LOGOUT_MAPPING = "/backchannellogout";

    private final SessionRegistry sessionRegistry;
    @Value("${spring.application.name}")
    private String applicationName;
    @Value("${govsso.logo}")
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
    public ModelAndView dashboard(@AuthenticationPrincipal OidcUser oidcUser) {
        ModelAndView model = new ModelAndView("dashboard");
        model.addObject("application_name", applicationName);
        model.addObject("application_logo", applicationLogo);

        log.info("Showing dashboard for subject='{}'", oidcUser.getSubject());
        addIdTokenDataToModel(oidcUser, model);

        return model;
    }

    @PostMapping(value = BACKCHANNEL_LOGOUT_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> backChannelLogout(@RequestParam(name = "logout_token") String logoutToken) {
        HttpHeaders responseHeaders = getHttpHeaders();
        DecodedJWT decodedLogoutToken = JWT.decode(logoutToken); //TODO remove com.auth0 dependency and use nimbus jwt instead
        log.info("Received back-channel logout request for sid='{}'", decodedLogoutToken.getClaim("sid"));
        expireOidcSessions(decodedLogoutToken.getClaim("sid").asString());
        return new ResponseEntity<>(responseHeaders, HttpStatus.OK);
    }

    private HttpHeaders getHttpHeaders() {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Cache-Control", "no-cache, no-store");
        responseHeaders.add("Pragma", "no-cache");
        return responseHeaders;
    }

    private void expireOidcSessions(String sid) {
        List<DefaultOidcUser> usersBySid =
                sessionRegistry.getAllPrincipals()
                        .stream()
                        .filter(principal -> principal instanceof DefaultOidcUser && (StringUtils.equals(((DefaultOidcUser) principal).getClaim("sid"), sid)))
                        .map(DefaultOidcUser.class::cast)
                        .collect(Collectors.toList());
        expireSessions(usersBySid);
    }

    private void expireSessions(List<DefaultOidcUser> users) {
        if (CollectionUtils.isEmpty(users)) {
            return;
        }
        for (DefaultOidcUser user : users) {
            for (SessionInformation si : sessionRegistry.getAllSessions(user, false)) {
                log.info("Terminating client application session sid='{}', sub='{}'", si.getSessionId(), user.getSubject());
                si.expireNow();
            }
        }
    }

    private void addIdTokenDataToModel(@AuthenticationPrincipal OidcUser oidcUser, ModelAndView model) {
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
        model.addObject("amr", oidcUser.getAuthenticationMethods());
        model.addObject("nonce", oidcUser.getNonce());
        model.addObject("acr", oidcUser.getAuthenticationContextClass());
        model.addObject("at_hash", oidcUser.getAccessTokenHash());
        model.addObject("sid", oidcUser.getIdToken().getClaim("sid"));
    }

}
