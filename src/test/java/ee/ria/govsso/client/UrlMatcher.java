package ee.ria.govsso.client;

import lombok.RequiredArgsConstructor;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;
import org.hamcrest.Matcher;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

// TODO: Improve error messages, currently all rules are printed if 1 fails and you can't tell which rule failed
public class UrlMatcher extends DiagnosingMatcher<String> {

    private final List<Rule> rules = new ArrayList<>();

    public static UrlMatcher url() {
        return new UrlMatcher();
    }

    public UrlMatcher scheme(Matcher<? super String> matcher) {
        rules.add(new Rule(
                new DelegatingMatcher<>(
                        UriComponents::getScheme,
                        matcher
                ),
                description -> {
                    description.appendText("scheme: ");
                    matcher.describeTo(description);
                }
        ));
        return this;
    }

    public UrlMatcher authority(Matcher<? super String> matcher) {
        rules.add(new Rule(
                new DelegatingMatcher<>(
                        uriComponents -> {
                            String uriString = UriComponentsBuilder.newInstance()
                                    .userInfo(uriComponents.getUserInfo())
                                    .host(uriComponents.getHost())
                                    .port(uriComponents.getPort())
                                    .toUriString();
                            java.util.regex.Matcher cleaningMatcher = Pattern.compile("^//(.*)$").matcher(uriString);
                            cleaningMatcher.matches();
                            return cleaningMatcher.group(1);
                        },
                        matcher
                ),
                description -> {
                    description.appendText("authority: ");
                    matcher.describeTo(description);
                }
        ));
        return this;
    }

    public UrlMatcher host(Matcher<? super String> matcher) {
        rules.add(new Rule(
                new DelegatingMatcher<>(
                        UriComponents::getHost,
                        matcher
                ),
                description -> {
                    description.appendText("host: ");
                    matcher.describeTo(description);
                }
        ));
        return this;
    }

    public UrlMatcher port(Matcher<? super Integer> matcher) {
        rules.add(new Rule(
                new DelegatingMatcher<>(
                        UriComponents::getPort,
                        matcher
                ),
                description -> {
                    description.appendText("port: ");
                    matcher.describeTo(description);
                }
        ));
        return this;
    }

    public UrlMatcher path(Matcher<? super String> matcher) {
        rules.add(new Rule(
                new DelegatingMatcher<>(
                        UriComponents::getPath,
                        matcher
                ),
                description -> {
                    description.appendText("path: ");
                    matcher.describeTo(description);
                }
        ));
        return this;
    }

    public UrlMatcher param(String name, Matcher<? super String> matcher) {
        rules.add(new Rule(
                new DelegatingMatcher<>(
                        uriComponents -> {
                            String encodedParamValue = uriComponents.getQueryParams().getFirst(name);
                            if (encodedParamValue == null) {
                                return null;
                            }
                            return UriUtils.decode(encodedParamValue, UTF_8);
                        },
                        matcher
                ),
                description -> {
                    description.appendText("query parameter \"" + name + "\": ");
                    matcher.describeTo(description);
                }
        ));
        return this;
    }

    @Override
    protected boolean matches(Object actual, Description mismatchDescription) {
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(((String) actual)).build();
        for (Rule rule : rules) {
            if (rule.matcher().matches(uriComponents)) {
                continue;
            }
            mismatchDescription.appendDescriptionOf(rule.matcher()).appendText(" ");
            rule.matcher().describeMismatch(actual, mismatchDescription);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        rules.stream()
                .map(Rule::describer)
                .forEach(describer -> {
                    description.appendText("\n\t");
                    describer.accept(description);
                });
    }

    @RequiredArgsConstructor
    private static class DelegatingMatcher<T> extends BaseMatcher<UriComponents> {

        private final Function<UriComponents, T> mapper;
        private final Matcher<? super T> delegate;

        @Override
        public boolean matches(Object actual) {
            return delegate.matches(mapper.apply((UriComponents) actual));
        }

        @Override
        public void describeTo(Description description) {
            delegate.describeTo(description);
        }
    }

    private record Rule(
            Matcher<UriComponents> matcher,
            Consumer<Description> describer
    ) {}

}
