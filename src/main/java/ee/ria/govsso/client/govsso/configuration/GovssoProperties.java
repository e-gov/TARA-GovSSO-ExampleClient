package ee.ria.govsso.client.govsso.configuration;

import ee.ria.govsso.client.govsso.configuration.condition.ConditionalOnGovsso;
import jakarta.validation.constraints.NotNull;
import ee.ria.govsso.client.oauth2.EidasLevelOfAssurance;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("govsso")
@ConditionalOnGovsso
public record GovssoProperties(
        @NotNull String clientId,
        @NotNull String clientSecret,
        @NotNull String redirectUri,
        @NotNull String issuerUri,
        @NotNull Resource trustStore,
        @NotNull String trustStorePassword,
        @NotNull String postLogoutRedirectUri,
        @NotNull EidasLevelOfAssurance minimumLoa
) {
}
