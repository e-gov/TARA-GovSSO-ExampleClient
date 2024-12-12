package ee.ria.govsso.client.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.experimental.UtilityClass;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.Locale;

import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

@UtilityClass
public class LogoutUtil {

    public String postLogoutRedirectUri(HttpServletRequest request, String postLogoutRedirectUri) {
        if (postLogoutRedirectUri == null) {
            return null;
        }
        UriComponents uriComponents = UriComponentsBuilder
                .fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();
        return UriComponentsBuilder.fromUriString(postLogoutRedirectUri)
                .buildAndExpand(Collections.singletonMap("baseUrl", uriComponents.toUriString()))
                .toUriString();
    }

    public String getUiLocale(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        } else if (session.getAttribute(LOCALE_SESSION_ATTRIBUTE_NAME) instanceof Locale locale) {
            return locale.getLanguage();
        } else {
            return null;
        }
    }
}
