package ee.ria.govsso.client;

import ee.ria.govsso.client.govsso.configuration.GovssoProperties;
import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT, classes = {
        Application.class, MockPropertyBeanConfiguration.class
})
public abstract class BaseTest {

    protected static GovssoMock govssoMock;

    @LocalServerPort
    protected int port;

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

    @BeforeEach
    void setUp() {
        RestAssured.filters(new ResponseLoggingFilter());
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
        RestAssured.requestSpecification = new RequestSpecBuilder()
                .setPort(port)
                .build();
        govssoMock.setGovssoProperties(govssoProperties);
    }
}
