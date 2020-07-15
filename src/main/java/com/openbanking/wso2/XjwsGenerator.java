package com.openbanking.wso2;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Map;
import java.security.Provider;
import java.security.Security;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.JWSHeader;
import org.jose4j.jws.JsonWebSignature;

public class XjwsGenerator {

    private static final String B64_CLAIM_KEY = "b64";
    // Key Id of the certificate
    private static final String KID_VALUE = "WXgaIj8ejRpLA6qkbTXXAdO_CQycptZxIKmyWz0lRXM";
    // Issued at timestamp
    private static final String IAT_VALUE = "1593561600";
    // Issuer of the certificate
    // If the application is created with a JWKS endpoint, then the ISS should be <org_id>/<software_id> of the JWKS
    private static final String ISS_VALUE = "CN=localhost,O=sample,L=Mountain View,ST=CA,C=US";
    // DNS name of the Trust Anchor
    private static final String TAN_VALUE = "openbanking.org.uk";
    // Password of the JKS
    private static final String KEYSTORE_PASSWORD = "admin";
    // Alias of the certificate in the JKS
    private static final String KEYSTORE_ALIAS = "localhost";
    // Absolute path of the JKS.
    private static final String KEYSTORE_PATH = "/home/abhishek/localhost.jks";

    public static void main(String[] args) {
        String REQUEST_HEADER = "{\n" +
                "\"alg\": \"PS256\",\n" +
                "\"kid\": \"" + KID_VALUE + "\",\n" +
                "\"b64\": false, \n" +
                "\"http://openbanking.org.uk/iat\": " + IAT_VALUE + ",\n" +
                "\"http://openbanking.org.uk/iss\": \"" + ISS_VALUE + "\",\n" +
                "\"http://openbanking.org.uk/tan\": \"" + TAN_VALUE + "\",\n" +
                "\"crit\": [ \"b64\", \"http://openbanking.org.uk/iat\",\n" +
                "\"http://openbanking.org.uk/iss\", \"http://openbanking.org.uk/tan\"] \n" +
                "}";

        // Compact payload for a sample domestic payment initiation
        String REQUEST_PAYLOAD = "{\"Data\":{\"Initiation\":{\"InstructionIdentification\":\"ABC12\",\"EndToEndIdentification\":\"ABC12\",\"InstructedAmount\":{\"Amount\":\"175.88\",\"Currency\":\"GBP\"},\"CreditorAccount\":{\"SchemeName\":\"UK.OBIE.SortCodeAccountNumber\",\"Identification\":\"1234\",\"Name\":\"ABC Inc\",\"SecondaryIdentification\":\"12345\"},\"RemittanceInformation\":{\"Reference\":\"ABC-123\",\"Unstructured\":\"Internal ops code 1234\"}}},\"Risk\":{\"PaymentContextCode\":\"EcommerceGoods\",\"MerchantCategoryCode\":\"1234\",\"MerchantCustomerIdentification\":\"1234\",\"DeliveryAddress\":{\"AddressLine\":[\"ABC\",\"DEF\"],\"StreetName\":\"GHI\",\"BuildingNumber\":\"1234\",\"PostCode\":\"1234\",\"TownName\":\"London\",\"CountrySubDivision\":[\"Wessex\"],\"Country\":\"UK\"}}}";

        String responseXjws = generateXJWSSignature(REQUEST_HEADER, REQUEST_PAYLOAD, KEYSTORE_PASSWORD, KEYSTORE_ALIAS, KEYSTORE_PATH);
        System.out.println("x-jws-signature: " + responseXjws);
    }

    public static String generateXJWSSignature(String requestHeader, String requestPayload, String keystorePassword, String keystoreAlias, String keystorePath) {

        char[] keyStorePassword = keystorePassword.toCharArray();

        try {
            Provider bc = BouncyCastleProviderSingleton.getInstance();
            Security.addProvider(bc);
            InputStream inputStream = new FileInputStream(keystorePath);
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(inputStream, keystorePassword.toCharArray());
            Key key = keyStore.getKey(keystoreAlias, keyStorePassword);

            if (key instanceof RSAPrivateKey) {

                JWSHeader jwsHeader = JWSHeader.parse(requestHeader);
                Object b64ValueObject = jwsHeader.getCustomParam(B64_CLAIM_KEY);
                boolean b64Value = b64ValueObject != null ? ((Boolean) b64ValueObject) : true;

                // Create a new JsonWebSignature
                JsonWebSignature jws = new JsonWebSignature();

                // Set the payload, or signed content, on the JWS object
                jws.setPayload(requestPayload);

                // Set the signature algorithm on the JWS that will integrity protect the payload
                jws.setAlgorithmHeaderValue(String.valueOf(jwsHeader.getAlgorithm()));

                // Setting headers
                jws.setKeyIdHeaderValue(jwsHeader.getKeyID());
                jws.setCriticalHeaderNames(jwsHeader.getCriticalParams().toArray(new String[0]));

                if (b64ValueObject != null) {
                    jws.getHeaders().setObjectHeaderValue(B64_CLAIM_KEY, b64Value);
                }

                for (Map.Entry<String, Object> entry : jwsHeader.getCustomParams().entrySet()) {
                    jws.getHeaders().setObjectHeaderValue(entry.getKey(), entry.getValue());
                }

                // Set the signing key on the JWS
                jws.setKey(key);

                // Sign the JWS and produce the detached JWS representation, which
                // is a string consisting of two dots ('.') separated base64url-encoded
                // parts in the form Header..Signature
                return jws.getDetachedContentCompactSerialization();
            }

        } catch (Exception e) {
            System.out.println("Something has gone wrong while generating the x-jws-signature. Please debug the source code.");
        }

        return " ";
    }

}
