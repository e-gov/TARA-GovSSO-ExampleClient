package ee.ria.govsso.client.configuration;

import ee.ria.govsso.client.filter.RequestCorrelationFilter;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class FilterConfiguration {

    @Bean
    public FilterRegistrationBean<RequestCorrelationFilter> requestCorrelationFilter(BuildProperties buildProperties) {
        FilterRegistrationBean<RequestCorrelationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new RequestCorrelationFilter(buildProperties));
        registrationBean.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
        return registrationBean;
    }
}
