package ee.ria.govsso.client.wiremock;

import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.matching.MatchResult;
import com.github.tomakehurst.wiremock.matching.ValueMatcher;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Objects;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class XWwwFormUrlencodedMatcher implements ValueMatcher<Request> {

    private final MultiValueMap<String, String> expectedBody;
    private final FormHttpMessageConverter messageConverter = new FormHttpMessageConverter();

    public static XWwwFormUrlencodedMatcherBuilder builder() {
        return new XWwwFormUrlencodedMatcherBuilder();
    }

    @Override
    public MatchResult match(Request request) {
        String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
        if (!StringUtils.startsWithIgnoreCase(contentType, MediaType.APPLICATION_FORM_URLENCODED_VALUE)) {
            return MatchResult.noMatch();
        }
        MultiValueMap<String, String> actualBody;
        try {
            actualBody = readBody(request);
        } catch (IOException e) {
            return MatchResult.noMatch();
        }
        if (!Objects.equals(actualBody, expectedBody)) {
            return MatchResult.noMatch();
        }
        return MatchResult.exactMatch();
    }

    private MultiValueMap<String, String> readBody(Request request) throws IOException {
        MockHttpInputMessage mockHttpMessage = new MockHttpInputMessage(request.getBody());
        mockHttpMessage.getHeaders().add(HttpHeaders.CONTENT_TYPE, request.getHeader(HttpHeaders.CONTENT_TYPE));
        return messageConverter.read(Foo.class, mockHttpMessage);
    }

    public static class XWwwFormUrlencodedMatcherBuilder {

        private final MultiValueMap<String, String> items = new LinkedMultiValueMap<>();

        public XWwwFormUrlencodedMatcherBuilder item(String key, String value) {
            this.items.add(key, value);
            return this;
        }

        public XWwwFormUrlencodedMatcher build() {
            return new XWwwFormUrlencodedMatcher(this.items);
        }
    }

    private interface Foo extends MultiValueMap<String, Object> {}
}
