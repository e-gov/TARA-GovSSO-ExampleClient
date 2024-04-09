package ee.ria.govsso.client.util;

import lombok.experimental.UtilityClass;

import java.util.Date;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

@UtilityClass
public class DemoResponseUtil {

    public Map<String, String> flattenClaims(Map<?, ?> claims) {
        SortedMap<String, String> flatClaims = new TreeMap<>();
        for (Map.Entry<?, ?> claim : claims.entrySet()) {
            java.lang.String key = claim.getKey().toString();
            Object value = claim.getValue();
            if (value instanceof Map<?, ?> innerClaims) {
                Map<java.lang.String, java.lang.String> flattenedInnerClaims = flattenClaims(innerClaims);
                for (Map.Entry<java.lang.String, java.lang.String> innerClaim : flattenedInnerClaims.entrySet()) {
                    flatClaims.put(key + "." + innerClaim.getKey(), innerClaim.getValue());
                }
                continue;
            }
            flatClaims.put(key, renderClaimValue(value));
        }
        return flatClaims;
    }

    private static String renderClaimValue(Object value) {
        if (value instanceof Date date) {
            return date.toInstant().toString();
        }
        return value.toString();
    }
}
