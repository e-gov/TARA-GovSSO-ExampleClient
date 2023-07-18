package ee.ria.govsso.client.tara.oauth2;

import ee.ria.govsso.client.oauth2.EidasLevelOfAssuranceValidator;
import ee.ria.govsso.client.tara.configuration.TaraProperties;
import ee.ria.govsso.client.tara.configuration.condition.ConditionalOnTara;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnTara
public class TaraLevelOfAssuranceValidator extends EidasLevelOfAssuranceValidator {

    public TaraLevelOfAssuranceValidator(
            TaraProperties properties,
            TaraLevelOfAssuranceValidationResultFactory validationResultFactory) {
        super(properties.minimumLoa(), validationResultFactory);
    }

}
