package ee.ria.govsso.client.govsso.configuration;

import ee.ria.govsso.client.configuration.ExampleClientSessionExpirationAuthenticationStrategy;
import ee.ria.govsso.client.configuration.ExampleClientSessionProperties;
import ee.ria.govsso.client.configuration.SecurityConstants;
import ee.ria.govsso.client.filter.ExampleClientSessionExpirationFilter;
import ee.ria.govsso.client.govsso.filter.GovssoSessionExpirationFilter;
import ee.ria.govsso.client.govsso.configuration.authentication.GovssoAuthentication;
import ee.ria.govsso.client.govsso.configuration.authentication.GovssoExampleClientUserFactory;
import ee.ria.govsso.client.govsso.filter.GovssoRefreshTokenFilter;
import ee.ria.govsso.client.govsso.filter.OidcBackChannelLogoutFilter;
import ee.ria.govsso.client.govsso.oauth2.GovssoAuthorizationRequestResolver;
import ee.ria.govsso.client.govsso.oauth2.GovssoClientInitiatedLogoutSuccessHandler;
import ee.ria.govsso.client.govsso.oauth2.GovssoLocalePassingLogoutHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.web.client.RestOperations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static ee.ria.govsso.client.configuration.CookieConfiguration.COOKIE_NAME_XSRF_TOKEN;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class GovssoSecurityConfiguration {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            GovssoProperties govssoProperties,
            @Qualifier("govssoRestTemplate") RestOperations govssoRestOperations,
            GovssoRefreshTokenTokenResponseClient refreshTokenTokenResponseClient,
            SessionRegistry sessionRegistry,
            GovssoIdTokenDecoderFactory idTokenDecoderFactory,
            OAuth2UserService<OidcUserRequest, OidcUser> userService,
            GovssoExampleClientUserFactory govssoExampleClientUserFactory,
            ExampleClientSessionProperties sessionProperties,
            Clock clock) throws Exception {
        // @formatter:off
        http
                .requestCache()
                    .requestCache(httpSessionRequestCache())
                    .and()
                .authorizeHttpRequests()
                    .antMatchers(
                            "/", "/assets/*", "/scripts/*", "/actuator/**")
                        .permitAll()
                    .requestMatchers(OidcBackChannelLogoutFilter.REQUEST_MATCHER)
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
                    .ignoringRequestMatchers(OidcBackChannelLogoutFilter.REQUEST_MATCHER)
                    .csrfTokenRepository(csrfTokenRepository())
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
                    .maxAgeInSeconds(Duration.ofDays(186).toSeconds())
                        .and()
                    .and()
                .oauth2Login()
                    .withObjectPostProcessor(new SetAuthenticationResultConverter(govssoExampleClientUserFactory))
                    .userInfoEndpoint()
                        .oidcUserService(userService)
                        .and()
                    .authorizationEndpoint()
                        .authorizationRequestResolver(
                                new GovssoAuthorizationRequestResolver(clientRegistrationRepository))
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
                            .logoutSuccessHandler(new GovssoClientInitiatedLogoutSuccessHandler(
                                    clientRegistrationRepository, govssoProperties.postLogoutRedirectUri()))
                            .getLogoutHandlers().add(0, new GovssoLocalePassingLogoutHandler());
                })
                .sessionManagement()
                     /*
                      * `.maximumSessions(...)` should always be configured as that makes sure a
                      * `ConcurrentSessionFilter` is created, which is required for our back-channel logout
                      * implementation to work. Without `ConcurrentSessionFilter`, expiring sessions from
                      * `SessionRegistry` would have no effect.
                      */
                    .sessionAuthenticationStrategy(
                            new CompositeSessionAuthenticationStrategy(List.of(
                                    new ChangeSessionIdAuthenticationStrategy(),
                                    new ExampleClientSessionExpirationAuthenticationStrategy(sessionProperties, clock)
                            ))
                    )
                    .maximumSessions(-1)
                    .expiredUrl("/?error=expired_session");
        // @formatter:on

        ExampleClientSessionExpirationFilter exampleClientSessionExpirationFilter =
                ExampleClientSessionExpirationFilter.builder()
                        .clock(clock)
                        .sessionProperties(sessionProperties)
                        .sessionRegistry(sessionRegistry)
                        .build();
        http.addFilterBefore(exampleClientSessionExpirationFilter, ConcurrentSessionFilter.class);

        OidcBackChannelLogoutFilter oidcBackchannelLogoutFilter = OidcBackChannelLogoutFilter.builder()
                .clientRegistrationRepository(clientRegistrationRepository)
                .sessionRegistry(sessionRegistry)
                .logoutTokenDecoderFactory(new GovssoLogoutTokenDecoderFactory(govssoRestOperations))
                .build();
        http.addFilterAfter(oidcBackchannelLogoutFilter, SessionManagementFilter.class);

        GovssoRefreshTokenFilter govssoRefreshTokenFilter = GovssoRefreshTokenFilter.builder()
                .oAuth2AuthorizedClientService(oAuth2AuthorizedClientService)
                .refreshTokenResponseClient(refreshTokenTokenResponseClient)
                .idTokenDecoderFactory(idTokenDecoderFactory)
                .userService(userService)
                .clientRegistrationRepository(clientRegistrationRepository)
                .govssoExampleClientUserFactory(govssoExampleClientUserFactory)
                .build();
        http.addFilterBefore(govssoRefreshTokenFilter, SessionManagementFilter.class);

        GovssoSessionExpirationFilter govssoSessionExpirationFilter = GovssoSessionExpirationFilter.builder()
                .clock(clock)
                .sessionRegistry(sessionRegistry)
                .build();
        http.addFilterBefore(govssoSessionExpirationFilter, ConcurrentSessionFilter.class);

        return http.build();
    }

    private static DefaultAuthorizationCodeTokenResponseClient createAccessTokenResponseClient(RestOperations govssoRestOperations) {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRestOperations(govssoRestOperations);
        return accessTokenResponseClient;
    }

    private HttpSessionRequestCache httpSessionRequestCache() {
        HttpSessionRequestCache httpSessionRequestCache = new HttpSessionRequestCache();
        // Disables session creation if session does not exist and any request returns 401 unauthorized error.
        httpSessionRequestCache.setCreateSessionAllowed(false);
        return httpSessionRequestCache;
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName(COOKIE_NAME_XSRF_TOKEN);
        repository.setSecure(true);
        repository.setCookiePath("/");
        return repository;
    }

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
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

    /* This is required, so we would have access to GovSSO refresh token without using `OAuth2AuthorizedClientService`
     * which has some issues - see `NoopAuthorizedClientService`.
     */
    @RequiredArgsConstructor
    private static class SetAuthenticationResultConverter
            implements ObjectPostProcessor<OAuth2LoginAuthenticationFilter> {

        private final GovssoExampleClientUserFactory govssoExampleClientUserFactory;

        @Override
        public <O extends OAuth2LoginAuthenticationFilter> O postProcess(O filter) {
            filter.setAuthenticationResultConverter(this::createGovssoAuthenticationToken);
            return filter;
        }

        private GovssoAuthentication createGovssoAuthenticationToken(
                OAuth2LoginAuthenticationToken authenticationResult
        ) {
            return new GovssoAuthentication(
                    authenticationResult.getPrincipal(),
                    authenticationResult.getAuthorities(),
                    authenticationResult.getClientRegistration().getRegistrationId(),
                    authenticationResult.getRefreshToken(),
                    govssoExampleClientUserFactory.create(authenticationResult.getPrincipal()));
        }

    }

}
