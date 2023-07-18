package ee.ria.govsso.client.govsso.configuration.condition;

import lombok.NonNull;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Set;

public class OnGovssoCondition implements Condition {

    public static final String GOVSSO_PROFILE = "govsso";

    @Override
    public boolean matches(ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
        Set<String> activeProfiles = Set.of(context.getEnvironment().getActiveProfiles());
        return activeProfiles.contains(GOVSSO_PROFILE);
    }

}

