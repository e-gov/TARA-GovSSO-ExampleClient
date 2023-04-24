package ee.ria.govsso.client.authentication;

import org.springframework.security.core.Authentication;

public interface ExampleClientAuthentication extends Authentication {

    ExampleClientUser getExampleClientUser();

}
