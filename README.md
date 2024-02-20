<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# TARA/GovSSO Example Client

Example client application that integrates with TARA service using the protocol specified
at https://e-gov.github.io/TARA-Doku/TechnicalSpecification and with GovSSO service using the protocol specified
at https://e-gov.github.io/GOVSSO/TechnicalSpecification. Demonstrates authentication, session update, RP-initiated
logout and back-channel logout flows (when applicable).

Example client contains support for both TARA and GovSSO in the code base, but can run in a single mode at a time (mode
must be set with a Spring profile). When developing your client application, implement only TARA or GovSSO support
depending on the service you are integrating with. OpenID Connect support for TARA and GovSSO integrations in example
client is based on the Spring Security framework's OAuth 2.0 module. **NB! Example client source code is provided for
study purposes and it cannot be used out of the box in production.**

**For TARA** demonstration and testing purposes, there are two publicly accessible deployments
of [example clients integrated with `tara-test.ria.ee`](https://e-gov.github.io/TARA-Doku/Demo):

* [https://tara-demo-client-publicsector.id.ee/](https://tara-demo-client-publicsector.id.ee/) - registered as a public
  sector client (TARA offers all authentication methods);
* [https://tara-demo-client-privatesector.id.ee/](https://tara-demo-client-privatesector.id.ee/) - registered as a
  private sector
  client ([TARA offers a subset of authentication methods](https://e-gov.github.io/TARA-Doku/TechnicalSpecification#9-private-sector-client-specifications)).

Example client in TARA mode can also be used with TARA mock. Visit https://github.com/e-gov/TARA-Mock for more
information.

**For GovSSO** demonstration and testing purposes, there are two publicly accessible deployments
of [example clients integrated with `govsso-demo.ria.ee`](https://e-gov.github.io/GOVSSO/Demo):

* [https://govsso-demo-client-a.id.ee/](https://govsso-demo-client-a.id.ee/)
* [https://govsso-demo-client-b.id.ee/](https://govsso-demo-client-b.id.ee/)

Example client in GovSSO mode can also be used with GovSSO mock. Visit https://github.com/e-gov/GOVSSO-Mock for more
information.

## Prerequisites

* Docker Engine
* Docker Compose (for running example client together with GOVSSO-Mock)
* Java 17 JDK (for building locally)

## Running pre-built public image in Docker Compose

1. Clone https://github.com/e-gov/GOVSSO-Mock repository
2. Follow [GOVSSO-Mock/README.md "Quick start"](https://github.com/e-gov/GOVSSO-Mock/blob/master/README.md#quick-start)
   instructions

## Running custom build in Docker Compose

1. Build
    * Either build in Docker
      ```shell
      docker run --pull always --rm \
                 -v /var/run/docker.sock:/var/run/docker.sock \
                 -v "$HOME/.m2:/root/.m2" \
                 -v "$PWD:/usr/src/project" \
                 -w /usr/src/project \
                 maven:3.9-eclipse-temurin-17 \
                 mvn spring-boot:build-image -DskipTests
      ```
      Git Bash users on Windows should add `MSYS_NO_PATHCONV=1` in front of the command
    * Or build locally
      ```shell
      ./mvnw spring-boot:build-image -DskipTests
      ```
3. Clone https://github.com/e-gov/GOVSSO-Mock repository
4. Open `GOVSSO-Mock/docker-compose.yml` and replace reference of pre-built public
   image `image: ghcr.io/e-gov/tara-govsso-exampleclient:x.y.z` with locally built
   image `image: tara-govsso-exampleclient:latest`
5. Follow [GOVSSO-Mock/README.md "Quick start"](https://github.com/e-gov/GOVSSO-Mock/blob/master/README.md#quick-start)
   instructions

## Endpoints

* https://client.localhost:11443/ - UI, end-user endpoints (requests initiated from web browsers)
* https://client.localhost:11443/oauth2/back-channel-logout/govsso - back-channel logout endpoint (requests initiated
  from GovSSO service)
* https://client.localhost:11443/actuator - maintenance endpoints

## Security operations

### Logout token

Security operations to verify the logout token are implemented as follows:

* **Verifying the signature:** handled by `org.springframework.security.oauth2.jwt.JwtDecoder`
  in `ee.ria.govsso.client.filter.OidcBackchannelLogoutFilter`
* **The trust of the public signature key endpoint:** SSL configuration is handled
  by `ee.ria.govsso.client.configuration.SSLConfig`
* **Verifying the issuer of tokens:** handled by `ee.ria.govsso.client.oauth2.OidcLogoutTokenValidator`
* **Verifying the addressee of the tokens:** handled by `ee.ria.govsso.client.oauth2.OidcLogoutTokenValidator`
* **Verifying the validity of the tokens:** handled by `ee.ria.govsso.client.oauth2.OidcLogoutTokenValidator`
