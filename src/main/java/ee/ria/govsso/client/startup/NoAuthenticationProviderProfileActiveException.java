package ee.ria.govsso.client.startup;

import java.util.Collection;

public class NoAuthenticationProviderProfileActiveException extends RuntimeException {

    public NoAuthenticationProviderProfileActiveException(Collection<String> authenticationProviderProfiles) {
        super("Failed to start application, no authentication provider profile active. " +
                "Available profiles: " + authenticationProviderProfiles);
    }
}
