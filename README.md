<img src="src/main/resources/static/assets/eu_regional_development_fund_horizontal.jpg" width="350" height="200" alt="European Union European Regional Development Fund"/>

# GOVSSO Example Client

TODO What this application does.

## Prerequisites

* Java 17 JDK

## Building and Running Locally

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
2. Run
   ```shell
   docker run --rm -p 11080:11080 govsso-client:latest
   ```

## Endpoints

* http://localhost:11080/ - UI
* http://localhost:11080/actuator/health
* http://localhost:11080/actuator/health/readiness
* http://localhost:11080/actuator/info

## Configuration

TODO
