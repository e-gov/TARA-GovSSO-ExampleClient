package ee.ria.govsso.client.configuration.govsso.authentication;

import ee.ria.govsso.client.authentication.ExampleClientAuthentication;
import ee.ria.govsso.client.authentication.ExampleClientUser;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;

@EqualsAndHashCode(callSuper = true)
@ToString
public class GovssoAuthentication extends OAuth2AuthenticationToken implements ExampleClientAuthentication {

    @Getter
    private final OAuth2RefreshToken refreshToken;
    private final ExampleClientUser user;

    public GovssoAuthentication(
            OAuth2User principal,
            Collection<? extends GrantedAuthority> authorities,
            String authorizedClientRegistrationId,
            OAuth2RefreshToken refreshToken,
            ExampleClientUser user) {
        super(principal, authorities, authorizedClientRegistrationId);
        this.refreshToken = refreshToken;
        this.user = user;
    }

    @Override
    public ExampleClientUser getExampleClientUser() {
        return this.user;
    }

}
