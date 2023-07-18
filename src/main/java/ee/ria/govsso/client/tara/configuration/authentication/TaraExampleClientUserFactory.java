package ee.ria.govsso.client.tara.configuration.authentication;

import ee.ria.govsso.client.authentication.ExampleClientUser;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;

import static java.util.Objects.requireNonNull;

@Component
@ConditionalOnTara
public class TaraExampleClientUserFactory {

    public ExampleClientUser create(OAuth2User taraOAuth2User) {
        Map<String, Object> profileAttributes = requireNonNull(taraOAuth2User.getAttribute("profile_attributes"));
        String fullNameWithIdCode = String.format(
                "%s %s (%s)",
                profileAttributes.get("given_name"),
                profileAttributes.get("family_name"),
                taraOAuth2User.getAttribute("sub"));
        return new ExampleClientUser(fullNameWithIdCode);
    }

}
