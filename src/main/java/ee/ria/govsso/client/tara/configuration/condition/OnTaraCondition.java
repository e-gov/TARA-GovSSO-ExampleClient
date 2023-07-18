package ee.ria.govsso.client.tara.configuration.condition;

import lombok.NonNull;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Set;

public class OnTaraCondition implements Condition {

    public static final String TARA_PROFILE = "tara";

    @Override
    public boolean matches(ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
        Set<String> activeProfiles = Set.of(context.getEnvironment().getActiveProfiles());
        return activeProfiles.contains(TARA_PROFILE);
    }

}

