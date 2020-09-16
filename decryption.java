package jwe;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;

public class Decrypt {

  private static final AlgorithmConstraints CONTENT_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
  private static final AlgorithmConstraints KEY_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
	
  private static final String PRIVATE_KEY = "MIIEvgIB...";
	
  public static void main(String[] args) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    byte[] binaryKey = Base64.getDecoder().decode(PRIVATE_KEY);
    RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(binaryKey));  		
    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setAlgorithmConstraints(KEY_ENCRYPTION_ALGORITHM_CONSTRAINTS);
    jwe.setContentEncryptionAlgorithmConstraints(CONTENT_ENCRYPTION_ALGORITHM_CONSTRAINTS);
    jwe.setKey(privateKey);
    jwe.setCompactSerialization("eyJhbGciOiJ...");
    Long iat = jwe.getHeaders().getLongHeaderValue("iat");
    System.out.println("iat:" + iat);
    String payload = jwe.getPayload();
    System.out.println(payload);
  }
}
