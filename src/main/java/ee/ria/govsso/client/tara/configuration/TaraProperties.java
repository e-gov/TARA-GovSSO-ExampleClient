package ee.ria.govsso.client.tara.configuration;

import ee.ria.govsso.client.oauth2.EidasLevelOfAssurance;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.util.List;

@Validated
@ConstructorBinding
@ConfigurationProperties("tara")
@ConditionalOnTara
public record TaraProperties(
        @NotNull String clientId,
        @NotNull String clientSecret,
        @NotNull String redirectUri,
        @NotNull List<String> scope,
        @NotNull String issuerUri,
        @NotNull Resource trustStore,
        @NotNull String trustStorePassword,
        @NotNull EidasLevelOfAssurance minimumLoa
) {}
