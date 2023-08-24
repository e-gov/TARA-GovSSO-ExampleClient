package ee.ria.govsso.client.startup;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static ee.ria.govsso.client.govsso.configuration.condition.OnGovssoCondition.GOVSSO_PROFILE;
import static ee.ria.govsso.client.tara.configuration.condition.OnTaraCondition.TARA_PROFILE;

@Slf4j
public class RequireAuthenticationProviderProfile {

    private static final Set<String> AUTHENTICATION_PROVIDER_PROFILES = Set.of(TARA_PROFILE, GOVSSO_PROFILE);

    public static void check(ApplicationContext applicationContext) {
        String[] activeProfiles = applicationContext.getEnvironment().getActiveProfiles();
        Set<String> activeAuthenticationProviderProfiles = Arrays.stream(activeProfiles)
                .filter(AUTHENTICATION_PROVIDER_PROFILES::contains)
                .collect(Collectors.toSet());
        if (activeAuthenticationProviderProfiles.isEmpty()) {
            throw new NoAuthenticationProviderProfileActiveException(AUTHENTICATION_PROVIDER_PROFILES);
        }
        if (activeAuthenticationProviderProfiles.size() > 1) {
            throw new MultipleAuthenticationProviderProfilesActiveException(activeAuthenticationProviderProfiles);
        }
    }

}
