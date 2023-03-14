package ee.ria.govsso.client.configuration.govsso;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.util.List;

@Validated
@ConstructorBinding
@ConfigurationProperties("govsso")
public record GovssoProperties(
        @NotNull String clientId,
        @NotNull String clientSecret,
        @NotNull String authorizationGrantType,
        @NotNull String redirectUri,
        @NotNull List<String> scope,
        @NotNull String issuerUri,
        @NotNull Resource trustStore,
        @NotNull String trustStorePassword,
        @NotNull String postLogoutRedirectUri
) {
}
