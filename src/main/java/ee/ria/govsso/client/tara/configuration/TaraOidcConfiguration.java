package ee.ria.govsso.client.tara.configuration;

import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
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
@ConditionalOnTara
public class TaraOidcConfiguration {

    public static final String TARA_REGISTRATION_ID = "tara";

    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
            @Autowired(required = false) OAuth2ClientProperties oAuth2ClientProperties,
            TaraProperties taraProperties,
            TaraClientRegistrationFactory clientRegistrationFactory
    ) {
        if (oAuth2ClientProperties != null) {
            verifyNoUnhandledOAuth2ClientConfiguration(oAuth2ClientProperties);
        }
        ClientRegistration taraClientRegistration =
                clientRegistrationFactory.createClientRegistration(TARA_REGISTRATION_ID, taraProperties);
        return new InMemoryClientRegistrationRepository(List.of(taraClientRegistration));
    }


    private void verifyNoUnhandledOAuth2ClientConfiguration(OAuth2ClientProperties oAuth2ClientProperties) {
        Set<String> registrationIds = oAuth2ClientProperties.getRegistration().keySet();
        Set<String> providerIds = oAuth2ClientProperties.getProvider().keySet();
        if (!registrationIds.isEmpty() || !providerIds.isEmpty()) {
            throw new IllegalArgumentException(
                    "This implementation does not support any OAuth client registrations in addition to TARA");
        }
    }

    @Bean
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return new OidcUserService();
    }

}
