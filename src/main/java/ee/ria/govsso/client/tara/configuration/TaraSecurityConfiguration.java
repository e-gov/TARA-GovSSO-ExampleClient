package ee.ria.govsso.client.tara.configuration;

import ee.ria.govsso.client.configuration.ExampleClientSessionExpirationAuthenticationStrategy;
import ee.ria.govsso.client.configuration.ExampleClientSessionProperties;
import ee.ria.govsso.client.configuration.SecurityConstants;
import ee.ria.govsso.client.filter.ExampleClientSessionExpirationFilter;
import ee.ria.govsso.client.tara.configuration.authentication.TaraAuthentication;
import ee.ria.govsso.client.tara.configuration.authentication.TaraExampleClientUserFactory;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import ee.ria.govsso.client.tara.oauth2.TaraAuthorizationRequestResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static ee.ria.govsso.client.configuration.CookieConfiguration.COOKIE_NAME_XSRF_TOKEN;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@ConditionalOnTara
public class TaraSecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            @Qualifier("taraRestOperations") RestOperations taraRestOperations,
            SessionRegistry sessionRegistry,
            OAuth2UserService<OidcUserRequest, OidcUser> userService,
            ClientRegistrationRepository clientRegistrationRepository,
            TaraExampleClientUserFactory exampleClientUserFactory,
            ExampleClientSessionProperties sessionProperties,
            Clock clock) throws Exception {
        // @formatter:off
        //noinspection Convert2MethodRef
        http
                .requestCache(requestCache -> requestCache
                        .requestCache(httpSessionRequestCache()))
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers(
                                new AntPathRequestMatcher("/"),
                                new AntPathRequestMatcher("/assets/**"),
                                new AntPathRequestMatcher("/webjars/**"),
                                new AntPathRequestMatcher("/scripts/**"),
                                new AntPathRequestMatcher("/styles/**"),
                                new AntPathRequestMatcher("/actuator/**"))
                            .permitAll()
                        .anyRequest()
                            .authenticated())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository()))
                .headers(headers -> headers
                        .xssProtection(xssProtection -> xssProtection
                                .disable())
                        .frameOptions(frameOptions -> frameOptions
                                .deny())
                        .contentSecurityPolicy(contentSecurityPolicy -> contentSecurityPolicy
                                .policyDirectives(SecurityConstants.CONTENT_SECURITY_POLICY))
                        .httpStrictTransportSecurity(httpStrictTransportSecurity -> httpStrictTransportSecurity
                                .maxAgeInSeconds(Duration.ofDays(186).toSeconds())))
                .oauth2Login(oauth2Login -> oauth2Login
                        .withObjectPostProcessor(new SetAuthenticationResultConverter(exampleClientUserFactory))
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .oidcUserService(userService))
                        .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                                .authorizationRequestResolver(
                                    new TaraAuthorizationRequestResolver(clientRegistrationRepository)))
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .accessTokenResponseClient(createAccessTokenResponseClient(taraRestOperations)))
                    .defaultSuccessUrl("/dashboard")
                    .failureHandler(getAuthFailureHandler()))
                .logout(logoutConfigurer -> {
                    logoutConfigurer.logoutUrl("/oauth/logout");
                    logoutConfigurer.logoutSuccessUrl("/?show-post-logout-message");
                })
                .sessionManagement(sessionManagement -> sessionManagement
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
                    .expiredUrl("/?error=expired_session"));
        // @formatter:on

        ExampleClientSessionExpirationFilter exampleClientSessionExpirationFilter =
                ExampleClientSessionExpirationFilter.builder()
                        .clock(clock)
                        .sessionProperties(sessionProperties)
                        .sessionRegistry(sessionRegistry)
                        .build();
        http.addFilterBefore(exampleClientSessionExpirationFilter, ConcurrentSessionFilter.class);
        return http.build();
    }

    private static DefaultAuthorizationCodeTokenResponseClient createAccessTokenResponseClient(
            RestOperations taraRestOperations) {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRestOperations(taraRestOperations);
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

        private final TaraExampleClientUserFactory exampleClientUserFactory;

        @Override
        public <O extends OAuth2LoginAuthenticationFilter> O postProcess(O filter) {
            filter.setAuthenticationResultConverter(this::createTaraAuthenticationToken);
            return filter;
        }

        private TaraAuthentication createTaraAuthenticationToken(
                OAuth2LoginAuthenticationToken authenticationResult
        ) {
            return new TaraAuthentication(
                    authenticationResult.getPrincipal(),
                    authenticationResult.getAuthorities(),
                    authenticationResult.getClientRegistration().getRegistrationId(),
                    exampleClientUserFactory.create(authenticationResult.getPrincipal()));
        }

    }

}
