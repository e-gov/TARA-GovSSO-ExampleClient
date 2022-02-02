package ee.ria.govsso.client;

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
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@DependsOn("SSLConfig")
@Slf4j
@Configuration
@ConfigurationProperties(prefix = "govsso")
@EnableWebSecurity
public class ApplicationConfiguration extends WebSecurityConfigurerAdapter {

    @Getter
    @Setter
    String publicUrl;
    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SessionRegistry sessionRegistry = sessionRegistry();
        http.sessionManagement().maximumSessions(1).sessionRegistry(sessionRegistry);
        CustomAuthorizationRequestResolver authorizationRequestResolver = new CustomAuthorizationRequestResolver(clientRegistrationRepository, sessionRegistry);

        http
                .authorizeRequests()
                .antMatchers("/", "/assets/*").permitAll()
                .anyRequest().authenticated()
                .and()
                .cors()
                .and()
                .formLogin()
                .loginPage("/")
                .and()
                .oauth2Login()
                .defaultSuccessUrl("/dashboard")
                .failureHandler(getAuthFailureHandler())
                .authorizationEndpoint().authorizationRequestResolver(authorizationRequestResolver);
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
}
