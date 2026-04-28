package ee.ria.govsso.client.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.logstash.logback.decorate.MapperBuilderDecorator;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class LogbackJsonFactoryDecorator
        implements MapperBuilderDecorator<JsonMapper, JsonMapper.Builder> {

    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    private static final SimpleDateFormat LOGSTASH_DATE_FORMAT =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    static {
        LOGSTASH_DATE_FORMAT.setTimeZone(UTC);
    }

    @Override
    public JsonMapper.Builder decorate(JsonMapper.Builder builder) {
        return builder
                .defaultDateFormat(LOGSTASH_DATE_FORMAT)
                .changeDefaultPropertyInclusion(inclusion ->
                        inclusion.withValueInclusion(JsonInclude.Include.NON_NULL))
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    }
}
