package ee.ria.govsso.client.startup;

import java.util.Collection;

public class MultipleAuthenticationProviderProfilesActiveException extends RuntimeException {

    public MultipleAuthenticationProviderProfilesActiveException(
            Collection<String> activeAuthenticationProviderProfiles
    ) {
        super("Failed to start application, multiple authentication provider profiles active. " +
                "Active authentication provider profiles: " + activeAuthenticationProviderProfiles);
    }
}
