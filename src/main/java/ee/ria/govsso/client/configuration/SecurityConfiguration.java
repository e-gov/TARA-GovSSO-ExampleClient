package ee.ria.govsso.client.configuration;

import ee.ria.govsso.client.configuration.govsso.GovssoLogoutTokenDecoderFactory;
import ee.ria.govsso.client.configuration.govsso.GovssoProperties;
import ee.ria.govsso.client.filter.OidcBackchannelLogoutFilter;
import ee.ria.govsso.client.oauth2.CustomAuthorizationRequestResolver;
import ee.ria.govsso.client.oauth2.CustomCsrfAuthenticationStrategy;
import ee.ria.govsso.client.oauth2.CustomOidcClientInitiatedLogoutSuccessHandler;
import ee.ria.govsso.client.oauth2.CustomRegisterSessionAuthenticationStrategy;
import ee.ria.govsso.client.oauth2.LocalePassingLogoutHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.web.client.RestOperations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static ee.ria.govsso.client.configuration.CookieConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.client.filter.OidcBackchannelLogoutFilter.OAUTH2_BACK_CHANNEL_LOGOUT_REQUEST_MATCHER;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private static final List<String> SESSION_UPDATE_CORS_ALLOWED_ENDPOINTS =
            Arrays.asList("/login/oauth2/code/govsso", "/dashboard");

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            GovssoProperties govssoProperties,
            @Qualifier("govssoRestTemplate") RestOperations govssoRestOperations) throws Exception {
        SessionRegistry sessionRegistry = sessionRegistry();

        // @formatter:off
        http
                .requestCache()
                    .requestCache(httpSessionRequestCache())
                    .and()
                .authorizeHttpRequests()
                    .antMatchers("/", "/assets/*", "/scripts/*", OAUTH2_BACK_CHANNEL_LOGOUT_REQUEST_MATCHER, "/actuator/**")
                        .permitAll()
                    .anyRequest()
                        .authenticated()
                    .and()
                /*
                    Using custom strategy since default one creates new CSRF token for each authentication,
                    but CSRF token should not change during authentication for GovSSO session update.
                    CSRF can be disabled if application does not manage its own session and cookies.
                 */
                .csrf()
                    .ignoringAntMatchers(OAUTH2_BACK_CHANNEL_LOGOUT_REQUEST_MATCHER)
                    .csrfTokenRepository(csrfTokenRepository())
                    .sessionAuthenticationStrategy(csrfSessionAuthStrategy())
                    .and()
                .headers()
                    .xssProtection().disable()
                    .frameOptions().deny()
                    .contentSecurityPolicy(SecurityConstants.CONTENT_SECURITY_POLICY)
                        /*
                         *  Prevents browser from blocking functionality if views do not meet CSP requirements.
                         *  Problems are still displayed at browser console.
                         *  TODO: Remove this once given problems are fixed.
                         */
                        .reportOnly()
                        .and()
                    .httpStrictTransportSecurity()
                    .maxAgeInSeconds(186 * 24 * 60 * 60)
                        .and()
                    .addHeaderWriter(corsHeaderWriter())
                        .and()
                .oauth2Login()
                    .authorizationEndpoint()
                        .authorizationRequestResolver(
                                new CustomAuthorizationRequestResolver(clientRegistrationRepository, sessionRegistry))
                        .and()
                    .tokenEndpoint()
                        .accessTokenResponseClient(createAccessTokenResponseClient(govssoRestOperations))
                        .and()
                    .defaultSuccessUrl("/dashboard")
                    .failureHandler(getAuthFailureHandler())
                    .and()
                .logout(logoutConfigurer -> {
                    logoutConfigurer.logoutUrl("/oauth/logout");
                    /*
                        Using custom handlers to pass ui_locales parameter to GovSSO logout flow.
                    */
                    logoutConfigurer
                            .logoutSuccessHandler(new CustomOidcClientInitiatedLogoutSuccessHandler(
                                    clientRegistrationRepository, govssoProperties.postLogoutRedirectUri()))
                            .getLogoutHandlers().add(0, new LocalePassingLogoutHandler());
                })
                .sessionManagement()
                     /*
                        Using custom authentication strategy to prevent creation of new application session during
                        each GovSSO session update.
                        Can be removed if stateless session policy is used.

                        ´.maximumSessions(1)´ should NOT be configured here, because it creates separate default
                        RegisterSessionAuthenticationStrategy that cannot be overridden.
                        If you want to configure maximum sessions then CompositeSessionAuthenticationStrategy containing
                        RegisterSessionAuthenticationStrategy and CustomRegisterSessionAuthenticationStrategy
                        must be passed.
                    */
                    /* TODO:
                        Filter out onAuthentication call before they reach session authentication strategies.
                        Initial call is made in https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/authentication/AbstractAuthenticationProcessingFilter.java#L228
                        a. If manage to override OAuth2LoginAuthenticationFilter, then its method attemptAuthentication
                        could return null in case of GovSSO session update.
                        But since given filter is not injectable as bean and registered automatically, it cannot be
                        overridden easily.
                        b. Also custom CompositeSessionAuthenticationStrategy can do the general filtering but unfortunately
                        implementation of it is not injectable as bean either. Every registered session authentication
                        strategy is always wrapped with it: https://github.com/spring-projects/spring-security/blob/81a930204568cd1d8a68ddc4da3a3c1bf0f66a2c/config/src/main/java/org/springframework/security/config/annotation/web/configurers/SessionManagementConfigurer.java#L507
                     */
                    .sessionAuthenticationStrategy(new CustomRegisterSessionAuthenticationStrategy(sessionRegistry))
                    .and()
                /* This example does not use Spring Session, thus user session storage is managed by the servlet
                 * container. Because there is no good way to query all the active sessions from the servlet container,
                 * we can't just delete all the relevant sessions when handling a back-channel logout request. Luckily
                 * for us, Spring Security provides a way to limit the number of concurrent sessions a single user can
                 * have, which just happens to have similar issues. This means we can use existing code meant to limit
                 * the number of concurrent sessions per user to make back-channel logout work.
                 *
                 * Back-channel logout expires relevant sessions from SessionRegistry but SessionRegistry is not used
                 * to read session data when handling a request. ConcurrentSessionFilter checks if the session at hand
                 * has been marked expired and performs logout if that is the case. Thus, ConcurrentSessionFilter is
                 * required to make back-channel logout work.
                 *
                 * TODO (GSSO-545): See if we could use `.sessionManagement().maximumSessions(-1)` instead of
                 *                  configuring `ConcurrentSessionFilter` manually
                 */
                .addFilter(concurrentSessionFilter());
        // @formatter:on

        OidcBackchannelLogoutFilter oidcBackchannelLogoutFilter = OidcBackchannelLogoutFilter.builder()
                .clientRegistrationRepository(clientRegistrationRepository)
                .sessionRegistry(sessionRegistry)
                .logoutTokenDecoderFactory(new GovssoLogoutTokenDecoderFactory(govssoRestOperations))
                .build();
        http.addFilterAfter(oidcBackchannelLogoutFilter, SessionManagementFilter.class);
        return http.build();
    }

    private static DefaultAuthorizationCodeTokenResponseClient createAccessTokenResponseClient(RestOperations govssoRestOperations) {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRestOperations(govssoRestOperations);
        return accessTokenResponseClient;
    }

    private ConcurrentSessionFilter concurrentSessionFilter() {
        return new ConcurrentSessionFilter(
                sessionRegistry(),
                new SimpleRedirectSessionInformationExpiredStrategy("/?error=expired_session"));
    }

    private HttpSessionRequestCache httpSessionRequestCache() {
        HttpSessionRequestCache httpSessionRequestCache = new HttpSessionRequestCache();
        // Disables session creation if session does not exist and any request returns 401 unauthorized error.
        httpSessionRequestCache.setCreateSessionAllowed(false);
        return httpSessionRequestCache;
    }

    private SessionAuthenticationStrategy csrfSessionAuthStrategy() {
        return new CustomCsrfAuthenticationStrategy(csrfTokenRepository());
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName(COOKIE_NAME_XSRF_TOKEN);
        repository.setSecure(true);
        repository.setCookiePath("/");
        return repository;
    }

    private HeaderWriter corsHeaderWriter() {
        return (request, response) -> {
            // CORS is needed for automatic, in the background session extension.
            // But only for the endpoint that GovSSO redirects to after successful re-authentication process.
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
    public SessionRegistry sessionRegistry() {
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
                if (exception instanceof OAuth2AuthenticationException ex) {
                    redirectStrategy.sendRedirect(request, response, "/?error=" + ex.getError().getErrorCode());
                } else {
                    redirectStrategy.sendRedirect(request, response, "/?error=authentication_failure");
                }
            }
        };
    }
}
