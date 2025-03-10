package ee.ria.govsso.client.govsso.oauth2;

import ee.ria.govsso.client.util.LogoutUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.Locale;

import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

/**
 * A custom logout handler for passing selected authentication locale to
 * {@link GovssoClientInitiatedLogoutSuccessHandler}, before session is invalidated by
 * {@link SecurityContextLogoutHandler}.
 *
 * @see GovssoAuthorizationRequestResolver
 */
public class GovssoLocalePassingLogoutHandler implements LogoutHandler {

    public static final String UI_LOCALES_PARAMETER = "ui_locales";

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String locale = LogoutUtil.getUiLocale(request);
        if (locale != null) {
            request.setAttribute(UI_LOCALES_PARAMETER, locale);
        }
    }
}
