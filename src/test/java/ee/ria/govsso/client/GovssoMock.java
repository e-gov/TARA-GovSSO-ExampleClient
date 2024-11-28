package ee.ria.govsso.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import ee.ria.govsso.client.govsso.configuration.GovssoProperties;
import ee.ria.govsso.client.wiremock.XWwwFormUrlencodedMatcher;
import lombok.Setter;
import lombok.SneakyThrows;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.util.Base64;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static java.util.Objects.requireNonNull;

public class GovssoMock implements AutoCloseable {

    private static final String FILES_FOLDER = "govsso_mock/";
    private static final String OPENID_CONFIGURATION_FILE_NAME = "openid-configuration.json";
    private static final String TOKEN_FILE_NAME = "token.json";

    private final WireMockServer server = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(13442)
            .keystorePath("src/test/resources/inproxy.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true)));
    private final RSAKey jwk = generateJwk();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Setter
    public GovssoProperties govssoProperties;

    public GovssoMock() {
        server.start();
        stubJwks();
        stubOpenidConfiguration();
    }

    @Override
    public void close() {
        server.stop();
    }

    @SneakyThrows
    private RSAKey generateJwk() {
        return new RSAKeyGenerator(4096)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
    }

    private void stubJwks() {
        JWKSet jwkSet = new JWKSet(this.jwk);
        server.stubFor(get(urlEqualTo("/.well-known/jwks.json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")
                        .withBody(jwkSet.toPublicJWKSet().toString())));
    }

    private void stubOpenidConfiguration() {
        server.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")
                        .withBodyFile(FILES_FOLDER + OPENID_CONFIGURATION_FILE_NAME)));
    }

    public void stubTokenEndpoint(String code, String nonce) {
        String tokenResponseTemplate = readFile(Path.of(FILES_FOLDER, TOKEN_FILE_NAME));
        String tokenResponse = tokenResponseTemplate.replace("<id-token>", toJsonString(createIdToken(nonce)));
        server.stubFor(post(urlEqualTo("/oauth2/token"))
                .withBasicAuth(govssoProperties.clientId(), govssoProperties.clientSecret())
                .andMatching(
                        XWwwFormUrlencodedMatcher.builder()
                                .item("code", code)
                                .item("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                                .item("redirect_uri", "https://clienta.localhost:11443/login/oauth2/code/govsso")
                                .build())
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")
                        .withBody(tokenResponse)));
    }

    public void stubLogoutEndpoint(String idTokenHint, String postLogoutRedirectUri) {
        server.stubFor(get(urlEqualTo("/oauth2/sessions/logout"))
                .withQueryParam("id_token_hint", equalTo(idTokenHint))
                .withQueryParam("post_logout_redirect_uri", equalTo(postLogoutRedirectUri))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")
                        .withHeader(HttpHeaders.LOCATION, postLogoutRedirectUri)));
    }

    // Creates a GovSSO spec compliant ID token, except the `exp` value is in year 2040.
    private String createIdToken(String nonce) {
        Base64.Encoder base64Encoder = Base64.getEncoder();

        String headerTemplate = readFile(Path.of(FILES_FOLDER, "id-token/header.json"));
        String headerJson = headerTemplate.replace("<kid>", toJsonString(jwk.getKeyID()));
        String header = base64Encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

        String bodyTemplate = readFile(Path.of(FILES_FOLDER, "id-token/body.json"));
        String bodyJson = bodyTemplate.replace("<nonce>", toJsonString(nonce));
        String body = base64Encoder.encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));

        byte[] signature = sign((header + "." + body).getBytes(StandardCharsets.UTF_8));

        return header + "." + body + "." + base64Encoder.encodeToString(signature);
    }

    @SneakyThrows
    private String toJsonString(String nonce) {
        return objectMapper.writeValueAsString(nonce);
    }

    @SneakyThrows
    private String readFile(Path filePath) {
        URL fileUrl = requireNonNull(getClass().getClassLoader().getResource(
                Path.of("__files").resolve(filePath).toString()));
        return Files.readString(Path.of(fileUrl.toURI()));
    }

    @SneakyThrows
    private byte[] sign(byte[] bytes) {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(jwk.toPrivateKey());
        privateSignature.update(bytes);
        return privateSignature.sign();
    }

}
