package ee.ria.govsso.client.govsso.oauth2;

import ee.ria.govsso.client.govsso.configuration.GovssoProperties;
import ee.ria.govsso.client.govsso.configuration.condition.ConditionalOnGovsso;
import ee.ria.govsso.client.oauth2.EidasLevelOfAssuranceValidator;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnGovsso
public class GovssoLevelOfAssuranceValidator extends EidasLevelOfAssuranceValidator {

    public GovssoLevelOfAssuranceValidator(
            GovssoProperties properties,
            GovssoLevelOfAssuranceValidationResultFactory validationResultFactory) {
        super(properties.minimumLoa(), validationResultFactory);
    }

}
