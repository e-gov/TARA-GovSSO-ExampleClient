package ee.ria.govsso.client.configuration;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.header.HeaderWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ORIGIN;

@DependsOn("SSLConfig")
@Slf4j
@Configuration
@ConfigurationProperties(prefix = "govsso")
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final List<String> SESSION_UPDATE_CORS_ALLOWED_ENDPOINTS =
            Arrays.asList("/login/oauth2/code/govsso", "/dashboard");

    @Getter
    @Setter
    String publicUrl;
    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SessionRegistry sessionRegistry = sessionRegistry();
        CustomAuthorizationRequestResolver authorizationRequestResolver = new CustomAuthorizationRequestResolver(clientRegistrationRepository, sessionRegistry);

        http
                .authorizeRequests()
                .antMatchers("/", "/assets/*").permitAll()
                .anyRequest().authenticated()
                .and()
                .headers()
                .addHeaderWriter(corsHeaderWriter())
                .and()
                .formLogin()
                .loginPage("/")
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .authorizationRequestResolver(authorizationRequestResolver)
                .and()
                .defaultSuccessUrl("/dashboard")
                .failureHandler(getAuthFailureHandler())
                .and()
                .logout()
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
                .logoutUrl("/oauth/logout")
                .deleteCookies().invalidateHttpSession(true)
                .and()
                .sessionManagement()
                .maximumSessions(1)
                .sessionRegistry(sessionRegistry)
                .expiredUrl("/?error=expired_session");
    }

    public HeaderWriter corsHeaderWriter() {
        return (request, response) -> {
            // CORS is needed for automatic, in the background session extension.
            // But only for the endpoint that GOVSSO redirects to after successful re-authentication process.
            // For that redirect Origin header is set to "null", since request comes from a "privacy-sensitive" context.
            // So setting CORS headers for given case only.
            // '/dashboard' must be included since the OAuth2 endpoint in turn redirects to dashboard.
            if (SESSION_UPDATE_CORS_ALLOWED_ENDPOINTS.contains(request.getRequestURI())) {
                String originHeader = request.getHeader(ORIGIN);
                if (originHeader != null && originHeader.equals("null")) {
                    response.addHeader(ACCESS_CONTROL_ALLOW_ORIGIN, "null");
                    response.addHeader(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                }
            }
        };
    }

    @Bean
    SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler getAuthFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler() {

            private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
                    throws IOException {
                log.error("Authentication failed", exception);
                redirectStrategy.sendRedirect(request, response, "/?error=authentication_failure");
            }
        };
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {

        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(publicUrl);
        return oidcLogoutSuccessHandler;
    }
}
