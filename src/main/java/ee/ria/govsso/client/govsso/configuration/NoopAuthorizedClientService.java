package ee.ria.govsso.client.govsso.configuration;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Component;

/* Implementations provided by Spring use the `sub` of the ID token as the key to the `OAuth2AuthorizedClient`. If a
 * single person is logged in multiple browsers concurrently, we can only keep track of one authorized client which
 * would cause all of those sessions to migrate to a single GovSSO session, which we obviously wouldn't want.
 *
 * Since we made refresh token part of `GovssoAuthenticationToken` we don't need to use `OAuth2AuthorizedClientService`
 * anyway.
 */
@Component
@Slf4j
public class NoopAuthorizedClientService implements OAuth2AuthorizedClientService {

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        throw new NotImplementedException();
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        log.debug("Not saving authorized client - using no-op implementation.");
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        log.debug("Not removing authorized client - using no-op implementation.");
    }
}
