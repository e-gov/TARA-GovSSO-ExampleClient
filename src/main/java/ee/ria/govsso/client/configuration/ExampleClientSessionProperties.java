package ee.ria.govsso.client.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties("example-client.session")
public record ExampleClientSessionProperties(
        Duration idleTimeout
) {}
