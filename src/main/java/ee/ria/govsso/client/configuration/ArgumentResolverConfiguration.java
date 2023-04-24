package ee.ria.govsso.client.configuration;

import ee.ria.govsso.client.authentication.ExampleClientUserResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ArgumentResolverConfiguration implements WebMvcConfigurer {

    private final ExampleClientUserResolver exampleClientUserResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(exampleClientUserResolver);
    }
}
