package ee.ria.govsso.client;

import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;

import static ee.ria.govsso.client.UrlMatcher.url;
import static ee.ria.govsso.client.controller.ClientController.DASHBOARD_MAPPING;
import static io.restassured.RestAssured.given;
import static java.util.Objects.requireNonNull;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

@ActiveProfiles(value = "govsso")
public class GovssoAuthenticationTest extends BaseTest {

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
                .header(HttpHeaders.LOCATION, url()
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
        String govssoAuthenticationRequestUrl = startAuthenticationResponse.header(HttpHeaders.LOCATION);
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
                .header(HttpHeaders.LOCATION, url()
                        .scheme(equalTo("http"))
                        .host(equalTo("localhost"))
                        .port(equalTo(port))
                        .path(equalTo("/dashboard")));

        given()
                .filter(cookieFilter)
                .when()
                .get(DASHBOARD_MAPPING)
                .then()
                .statusCode(200)
                .body(containsString("id=\"access_token\">eyJhbGciOiJSUzI1NiIsImtpZCI6IjJiMDZiMjNmLTI2MDMtNGMxYy05OWU2LWRmOTVjYjRlMzAwMSIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbIm1JRCJdLCJhdWQiOlsiaHR0cHM6Ly90ZXN0Il0sImJpcnRoZGF0ZSI6IjE5NjEtMDctMTIiLCJjbGllbnRfaWQiOiJjbGllbnQtYSIsImV4cCI6MTcxMDgzMzk2MywiZXh0Ijp7ImFjciI6ImhpZ2giLCJhbXIiOlsibUlEIl0sImJpcnRoZGF0ZSI6IjE5NjEtMDctMTIiLCJmYW1pbHlfbmFtZSI6IlBlcmVrb25uYW5pbWkzIiwiZ2l2ZW5fbmFtZSI6IkVlc25pbWkzIn0sImZhbWlseV9uYW1lIjoiUGVyZWtvbm5hbmltaTMiLCJnaXZlbl9uYW1lIjoiRWVzbmltaTMiLCJpYXQiOjE3MTA4MzM5NjIsImlzcyI6Imh0dHBzOi8vaW5wcm94eS5sb2NhbGhvc3Q6MTM0NDMvIiwianRpIjoiYWFjMmM4ZDEtYTNiMy00MmM1LWEzYzQtZTc4ZGIyZTc1NWNmIiwic2NwIjpbIm9wZW5pZCJdLCJzdWIiOiJJc2lrdWtvb2QzIn0.ZLVYuMPTrz-D8XIfc_V1DnAwfBGDD02IjUIKNPstwKmN3WcWPFL1utjDtbo3oGPoQvWEZYBfnpXOdAFYYcnBax7Aj4cUW1uamz0rKGInOE_-0o66Go9bMqJ5sA9mJn5EYS293SYsfDaFLz_P598FNohAIlovJj2CgYRQI7JPHkIBGKDKYGprQ-QywB13qEamosDGII1DH_RtCwWcqn5QEHzbsbuoARNXZ28G4vLpihuCKl-aHUDnms5vTsZRaeiR6YyAxJYkJdUG7FKE6c5ocLmp29aN19jIANpoiDLsGVATuoqFns0VwnVaXugMpAMvgscb29hItvoQlrwyKlbrPwRRHpdBP4L74kMxL5u8yTjVgTlnySKtc7YmJfXdpBUcRedsdTu4qsApzPkLASr0x7hSiclHYUtR1s9mDhuZH38_gsa43cVhOsayoeH-Fdr8hGvqTCihVlsFdWgd0fLfXYRqXDz9lPLpphMdJty1iQ1DSG5jSVaoaT-e1JSHNXCH1I21AomxWp5cvrEbK9VmaAeT6lelReVADeTJg1pBBUx_mJVxnh_Js0LrJrtxHRV-OWNo4kCBVYUjtJFsjvPovKR8dSGt1KzuCLKehKo5JNM4wiM4-hXMiwLkjE-qOYazMapGmqrXU-ijV3lOr0DROnB8fBWLl3j2FoHiQ9a0nbY"))
                .body(containsString("id=\"refresh_token\">XF-G7eKbiuZ0eaUaZY7WZsz70Jmm0Tro6AiTyeQcULU.Xh4GpFqcJ-vatFArYknlH6dbY8FfnxaC3xf-uzLHhPY"));
    }

    private static String getQueryParam(UriComponents locationComponents, String paramName) {
        String paramValue = locationComponents.getQueryParams().getFirst(paramName);
        return UriUtils.decode(requireNonNull(paramValue), StandardCharsets.UTF_8);
    }

}
