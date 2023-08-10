package ee.ria.govsso.client.govsso.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.List;
import java.util.Set;

@Configuration
@Slf4j
public class GovssoOidcConfiguration {

    public static final String GOVSSO_REGISTRATION_ID = "govsso";

    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
            @Autowired(required = false) OAuth2ClientProperties oAuth2ClientProperties,
            GovssoProperties govssoProperties,
            GovssoClientRegistrationFactory govssoClientRegistrationFactory
    ) {
        if (oAuth2ClientProperties != null) {
            verifyNoUnhandledOAuth2ClientConfiguration(oAuth2ClientProperties);
        }
        ClientRegistration govSsoClientRegistration =
                govssoClientRegistrationFactory.createClientRegistration(GOVSSO_REGISTRATION_ID, govssoProperties);
        return new InMemoryClientRegistrationRepository(List.of(govSsoClientRegistration));
    }


    private void verifyNoUnhandledOAuth2ClientConfiguration(OAuth2ClientProperties oAuth2ClientProperties) {
        Set<String> registrationIds = oAuth2ClientProperties.getRegistration().keySet();
        Set<String> providerIds = oAuth2ClientProperties.getProvider().keySet();
        if (!registrationIds.isEmpty() || !providerIds.isEmpty()) {
            throw new IllegalArgumentException(
                    "This implementation does not support any OAuth client registrations in addition to GovSSO");
        }
    }

    @Bean
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return new OidcUserService();
    }

}
