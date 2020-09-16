package jwe;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;

public class Encrypt {
	
  private static String PUBLIC_KEY = "MIIBIjAN...";

  public static void main(String[] args) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    byte[] binaryKey = Base64.getDecoder().decode(PUBLIC_KEY);
    RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(new X509EncodedKeySpec(binaryKey));  		
    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setPayload("{\"name\":\"pass1\",\"value\":\"secret1\",\"username\":\"user1\"}");
    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    jwe.setKey(publicKey);
    long iat = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    jwe.getHeaders().setObjectHeaderValue("iat", iat);
    String jweCompact = jwe.getCompactSerialization();
    System.out.println(jweCompact);
  }
}
