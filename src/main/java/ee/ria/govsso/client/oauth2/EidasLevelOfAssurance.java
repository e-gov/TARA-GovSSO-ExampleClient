package ee.ria.govsso.client.oauth2;

public enum EidasLevelOfAssurance implements Comparable<EidasLevelOfAssurance> {
    LOW, SUBSTANTIAL, HIGH;

    public static EidasLevelOfAssurance fromValue(String value) {
        return EidasLevelOfAssurance.valueOf(value.toUpperCase());
    }

    public boolean isAtLeast(EidasLevelOfAssurance minimumLevel) {
        return compareTo(minimumLevel) >= 0;
    }
}
