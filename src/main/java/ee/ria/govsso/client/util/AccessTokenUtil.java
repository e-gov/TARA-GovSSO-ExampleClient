package ee.ria.govsso.client.util;

import com.nimbusds.jwt.JWTParser;
import lombok.experimental.UtilityClass;

import java.text.ParseException;

@UtilityClass
public class AccessTokenUtil {

    public boolean isJwtAccessToken(String accessToken) {
        try {
            JWTParser.parse(accessToken);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }
}
