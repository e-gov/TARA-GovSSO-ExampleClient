package ee.ria.govsso.client;

import lombok.Setter;
import lombok.SneakyThrows;
import org.apache.hc.core5.net.URIBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.unit.DataSize;
import org.springframework.web.bind.annotation.GetMapping;

import java.net.URI;

import static io.restassured.RestAssured.given;


@ActiveProfiles(value = "govsso")
@Import(LongResponseHeaderTest.RedirectToLongUrlController.class)
public class LongResponseHeaderTest extends BaseTest {

    public static final String LONG_PARAM_NAME = "longParam";
    public static final String LONG_PARAM_VALUE = "a".repeat((int) DataSize.ofKilobytes(127).toBytes());

    @Autowired
    private RedirectToLongUrlController redirectToLongUrlController;

    @Test
    @SneakyThrows
    void outgoingRequest_urlLengthAlmost128Kb_requestHandledSuccessfully() {
        URI redirectUrl = new URIBuilder()
                .setPath("/")
                .setParameter(LONG_PARAM_NAME, LONG_PARAM_VALUE)
                .build();
        redirectToLongUrlController.setRedirectUrl(redirectUrl);

        given()
                .when()
                .redirects().follow(false)
                .get("/assets/redirect")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, redirectUrl.toString());
    }

    @Controller
    @Setter
    public static class RedirectToLongUrlController {

        private URI redirectUrl;

        /**
         * Use `/assets` prefix in order to not require user authentication, see
         * {@link ee.ria.govsso.client.govsso.configuration.GovssoSecurityConfiguration}
         */
        @GetMapping("/assets/redirect")
        public ResponseEntity<?> longRedirect() {
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(redirectUrl);
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

    }

}
