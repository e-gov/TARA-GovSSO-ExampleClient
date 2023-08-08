package ee.ria.govsso.client;

import ee.ria.govsso.client.govsso.configuration.GovssoProperties;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;

import static ee.ria.govsso.client.UrlMatcher.url;
import static io.restassured.RestAssured.given;
import static java.util.Objects.requireNonNull;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

@ActiveProfiles(value = "govsso")
public class GovssoAuthenticationTest extends BaseTest {

    private static final String LOCATION_HEADER = "Location";

    private static GovssoMock govssoMock;

    @Autowired
    public GovssoProperties govssoProperties;

    @BeforeAll
    static void beforeAll() {
        govssoMock = new GovssoMock();
    }

    @AfterAll
    @SneakyThrows
    static void afterAll() {
        try {
            if (govssoMock != null) {
                govssoMock.close();
            }
        } finally {
            govssoMock = null;
        }
    }

    @Override
    @BeforeEach
    void setUp() {
        super.setUp();
        govssoMock.setGovssoProperties(govssoProperties);
    }

    @Test
    public void applicationStartup() {
    }

    @Test
    @SneakyThrows
    public void authentication() {
        String code = "randomly-generated-code";
        CookieFilter cookieFilter = new CookieFilter();
        ExtractableResponse<Response> startAuthenticationResponse = given()
                .filter(cookieFilter)
                .when()
                .get("oauth2/authorization/govsso")
                .then()
                .assertThat()
                .statusCode(302)
                .header(LOCATION_HEADER, url()
                        .scheme(equalTo("https"))
                        .authority(equalTo("inproxy.localhost:13442"))
                        .path(equalTo("/oauth2/auth"))
                        .param("response_type", equalTo("code"))
                        .param("scope", equalTo("openid"))
                        .param("state", notNullValue())
                        .param("nonce", notNullValue())
                        .param("client_id", equalTo(govssoProperties.clientId()))
                        .param("redirect_uri", equalTo(govssoProperties.redirectUri())))
                .extract();
        String govssoAuthenticationRequestUrl = startAuthenticationResponse.header(LOCATION_HEADER);
        UriComponents locationComponents = UriComponentsBuilder.fromUriString(govssoAuthenticationRequestUrl).build();
        String state = getQueryParam(locationComponents, "state");
        String nonce = getQueryParam(locationComponents, "nonce");

        govssoMock.stubTokenEndpoint(code, nonce);
        String completeAuthenticationUrl = UriComponentsBuilder.fromPath("/login/oauth2/code/govsso")
                .queryParam("code", code)
                .queryParam("state", state)
                .build()
                .toUriString();
        given()
                .filter(cookieFilter)
                .when()
                .get(completeAuthenticationUrl)
                .then()
                .statusCode(302)
                .header(LOCATION_HEADER, url()
                        .scheme(equalTo("http"))
                        .host(equalTo("localhost"))
                        .port(equalTo(port))
                        .path(equalTo("/dashboard")));
    }

    private static String getQueryParam(UriComponents locationComponents, String paramName) {
        String paramValue = locationComponents.getQueryParams().getFirst(paramName);
        return UriUtils.decode(requireNonNull(paramValue), StandardCharsets.UTF_8);
    }

}
