package ee.ria.govsso.client.configuration.govsso;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;

@Getter
@EqualsAndHashCode(callSuper = true)
@ToString
public class GovssoAuthenticationToken extends OAuth2AuthenticationToken {

    private final OAuth2RefreshToken refreshToken;

    public GovssoAuthenticationToken(
            OAuth2User principal,
            Collection<? extends GrantedAuthority> authorities,
            String authorizedClientRegistrationId,
            OAuth2RefreshToken refreshToken) {
        super(principal, authorities, authorizedClientRegistrationId);
        this.refreshToken = refreshToken;
    }

}
