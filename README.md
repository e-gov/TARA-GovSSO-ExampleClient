<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GovSSO Example Client

Example client application that integrates with GovSSO service with protocol specified
at https://e-gov.github.io/GOVSSO/TechnicalSpecification . Demonstrates authentication, session update, RP-initiated
logout and back-channel logout flows.

## Prerequisites

* Java 17 JDK

## Building and Running Locally

1. Follow [GOVSSO-Session/README.md](https://github.com/e-gov/GOVSSO-Session/blob/master/README.md) to run dependent
   services.
2. If you have generated new TLS certificates (doable at project GOVSSO-Session) after the last copy, then copy-replace
   `clienta.localhost.keystore.p12` and `clienta.localhost.truststore.p12` files to `src/main/resources`.
3. Add `127.0.0.1 gateway.localhost` line to `hosts` file. This is needed only for requests originating from
   GOVSSO-Client when it's running locally (not in Docker Compose). It's not needed for web browsers as popular browsers
   already have built-in support for resolving `*.localhost` subdomains.
4. Run
   ```shell 
   ./mvnw spring-boot:run
   ```

## Running in Docker

1. Build
    * Either build locally
      ```shell
      ./mvnw spring-boot:build-image
      ```
    * Or build in Docker
      ```shell
      docker run --pull always --rm \
                 -v /var/run/docker.sock:/var/run/docker.sock \
                 -v "$HOME/.m2:/root/.m2" \
                 -v "$PWD:/usr/src/project" \
                 -w /usr/src/project \
                 maven:3.8.2-openjdk-17 \
                 mvn spring-boot:build-image
      ```
      Git Bash users on Windows should add `MSYS_NO_PATHCONV=1` in front of the command.
2. Follow GOVSSO-Session/README.md to run GOVSSO-Client and dependent services inside Docker Compose

## Endpoints

* http://localhost:11443/ - UI
* http://localhost:11443/actuator - maintenance endpoints
