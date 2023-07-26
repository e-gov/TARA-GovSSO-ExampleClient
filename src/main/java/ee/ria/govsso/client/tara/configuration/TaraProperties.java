package ee.ria.govsso.client.tara.configuration;

import ee.ria.govsso.client.oauth2.EidasLevelOfAssurance;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("tara")
@ConditionalOnTara
public record TaraProperties(
        @NotNull String clientId,
        @NotNull String clientSecret,
        @NotNull String redirectUri,
        @NotNull String issuerUri,
        @NotNull Resource trustStore,
        @NotNull String trustStorePassword,
        @NotNull EidasLevelOfAssurance minimumLoa
) {}
