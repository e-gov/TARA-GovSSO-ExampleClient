package ee.ria.govsso.client.configuration;

import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/*
 NB! Following cookie settings do not work with standalone Tomcat and are configured
 in context.xml instead (look at webapp/META-INF/context.xml).
*/
@Configuration(proxyBeanMethods = false)
public class CookieConfiguration {

    public static final String COOKIE_NAME_SESSION = "__Host-SESSION";
    public static final String COOKIE_NAME_XSRF_TOKEN = "__Host-XSRF-TOKEN";

    /*
     For session cookie 'SameSite=Lax' is needed (cannot be 'Strict'), because this cookie needs to be
     read when redirected back to given client application after authentication at govsso.ria.ee domain.
     */
    @Bean
    CookieSameSiteSupplier sessionCookieSameSiteSupplier() {
        return CookieSameSiteSupplier.ofLax().whenHasName(COOKIE_NAME_SESSION);
    }

    /*
     CSRF cookie is also passed with govsso.ria.ee authentication redirect, but it being 'SameSite=Strict'
     means browser will ignore it, resulting with spring regenerating it.
     Does not actually cause any issues but maybe consider turning it to 'Lax'.

     NB! Since standalone Tomcat configuration changes session related cookies SameSite globally and
     session cookie MUST be 'Lax', then it's SameSite is also 'Lax' in standalone Tomcat.
     */
    @Bean
    CookieSameSiteSupplier csrfCookieSameSiteSupplier() {
        return CookieSameSiteSupplier.ofStrict().whenHasName(COOKIE_NAME_XSRF_TOKEN);
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> servletContext.getSessionCookieConfig().setName(COOKIE_NAME_SESSION);
    }
}
