package ee.ria.govsso.client.govsso.configuration.authentication;

import ee.ria.govsso.client.authentication.ExampleClientUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class GovssoExampleClientUserFactory {

    public ExampleClientUser create(OAuth2User govssoOAuth2User) {
        String fullNameWithIdCode = String.format(
                "%s %s (%s)",
                govssoOAuth2User.getAttribute("given_name"),
                govssoOAuth2User.getAttribute("family_name"),
                govssoOAuth2User.getAttribute("sub"));
        return new ExampleClientUser(fullNameWithIdCode);
    }

}
