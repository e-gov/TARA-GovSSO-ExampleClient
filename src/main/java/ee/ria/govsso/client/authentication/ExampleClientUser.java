package ee.ria.govsso.client.authentication;

/* The purpose of this record is to demo how an application could have its own user data class which could include
 * data that is not present in the ID token provided OAuth provider.
 */
public record ExampleClientUser(
    String fullNameWithIdCode
) {}
