import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class Encryption {
  public static String EC_ALGO = "secp256r1";
  public static String AES_ALGO = "AES/GCM/NoPadding";
  public static Integer AES_IV_LEN = 16;
  public static Integer AES_KEY_LEN = 256;
  public static Integer AES_GCM_TAG_LEN = 16;
  public static Integer UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
  public static String CONTENT_ENCODING = "base64";
  public static byte UNCOMPRESSED_POINT_INDICATOR = 0x04;
  public static int EC_PUB_KEY_BYTE_SIZE = 32;

  public static ECPrivateKey readPrvKeyFromPemFile(String pemFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    PemReader pemReader = new PemReader(new FileReader(pemFile));
    PemObject pemObject = pemReader.readPemObject();
    byte[] pemContent = pemObject.getContent();
    pemReader.close();
    PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemContent);
    return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(encodedKeySpec);
  }

  public static ECPublicKey readPubKeyFromPemFile(String pemFile) throws IOException, CertificateException {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    FileInputStream certInputStream = new FileInputStream(pemFile);
    X509Certificate cer = (X509Certificate) factory.generateCertificate(certInputStream);
    return (ECPublicKey) cer.getPublicKey();
  }

  public static ECPublicKey fromUncompressedPoint(byte[] uncompressedPoint) throws Exception {
    int offset = 0;
    if (uncompressedPoint[offset++] != UNCOMPRESSED_POINT_INDICATOR) {
      throw new IllegalArgumentException("Invalid uncompressedPoint encoding, no uncompressed point indicator");
    }
    int keySizeBytes = EC_PUB_KEY_BYTE_SIZE;
    if (uncompressedPoint.length != 1 + 2 * keySizeBytes) {
      throw new IllegalArgumentException("Invalid uncompressedPoint encoding, not the correct size");
    }
    BigInteger x = new BigInteger(
      1,
      Arrays.copyOfRange(uncompressedPoint, offset, offset + keySizeBytes)
    );
    offset += keySizeBytes;
    BigInteger y = new BigInteger(
      1,
      Arrays.copyOfRange(uncompressedPoint, offset, offset + keySizeBytes)
    );
    ECPoint w = new ECPoint(x, y);
    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(EC_ALGO);
    ECParameterSpec spec = new ECNamedCurveSpec(
      EC_ALGO,
      parameterSpec.getCurve(),
      parameterSpec.getG(),
      parameterSpec.getN(),
      parameterSpec.getH(),
      parameterSpec.getSeed()
    );
    ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, spec);
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
  }

  public static byte[] toUncompressedPoint(final ECPublicKey publicKey) {
    int keySizeBytes = EC_PUB_KEY_BYTE_SIZE;
    byte[] uncompressedPoint = new byte[1 + 2 * keySizeBytes];
    int offset = 0;
    uncompressedPoint[offset++] = 0x04;
    byte[] x = publicKey.getW().getAffineX().toByteArray();
    if (x.length <= keySizeBytes) {
      System.arraycopy(x, 0, uncompressedPoint, offset + keySizeBytes - x.length, x.length);
    } else if (x.length == keySizeBytes + 1 && x[0] == 0) {
      System.arraycopy(x, 1, uncompressedPoint, offset, keySizeBytes);
    } else {
      throw new IllegalStateException("x value is too large");
    }
    offset += keySizeBytes;
    byte[] y = publicKey.getW().getAffineY().toByteArray();
    if (y.length <= keySizeBytes) {
      System.arraycopy(y, 0, uncompressedPoint, offset + keySizeBytes - y.length, y.length);
    } else if (y.length == keySizeBytes + 1 && y[0] == 0) {
      System.arraycopy(y, 1, uncompressedPoint, offset, keySizeBytes);
    } else {
      throw new IllegalStateException("y value is too large");
    }

    return uncompressedPoint;
  }

  public static byte[] randomBytes(Integer len) {
    SecureRandom rnd = new SecureRandom();
    byte[] bytes = new byte[len];
    rnd.nextBytes(bytes);
    return bytes;
  }

  public static byte[] aesEncrypt(byte[] key, byte[] originalBytes) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
    byte[] iv = randomBytes(AES_IV_LEN);
    Cipher cipher = Cipher.getInstance(AES_ALGO);
    // Create SecretKeySpec
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    // Create GCMParameterSpec
    GCMParameterSpec gcmParamSpec = new GCMParameterSpec(AES_GCM_TAG_LEN * 8, iv);
    // Initialize Cipher for ENCRYPT_MODE
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParamSpec);
    // Perform Encryption
    byte[] encryptedWithTag = cipher.doFinal(originalBytes);
    byte[] tag = Arrays.copyOfRange(
      encryptedWithTag,
      encryptedWithTag.length - AES_GCM_TAG_LEN,
      encryptedWithTag.length
    );
    byte[] encrypted = Arrays.copyOfRange(
      encryptedWithTag,
      0,
      encryptedWithTag.length - AES_GCM_TAG_LEN
    );
    byte[] prefix = ByteUtils.concatenate(iv, tag);
    return ByteUtils.concatenate(prefix, encrypted);
  }

  public static byte[] aesDecrypt(byte[] key, byte[] encryptedBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, AES_IV_LEN);
    byte[] tag = Arrays.copyOfRange(
      encryptedBytes,
      AES_IV_LEN,
      AES_IV_LEN + AES_GCM_TAG_LEN
    );
    byte[] encrypted = Arrays.copyOfRange(
      encryptedBytes,
      AES_IV_LEN + AES_GCM_TAG_LEN,
      encryptedBytes.length
    );
    // Get Cipher Instance
    Cipher cipher = Cipher.getInstance(AES_ALGO);
    // Create SecretKeySpec
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    // Create GCMParameterSpec
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AES_GCM_TAG_LEN * 8, iv);
    // Initialize Cipher for DECRYPT_MODE
    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
    // Perform Decryption
    cipher.update(encrypted);
    return cipher.doFinal(tag);
  }

  public static String encrypt(ECPublicKey senderPubKey, String msg) throws Exception {
    ECGenParameterSpec ecKeyGenSpec = new ECGenParameterSpec(EC_ALGO);
    KeyPairGenerator ecKeyPairGenerator = KeyPairGenerator.getInstance("EC");
    ecKeyPairGenerator.initialize(ecKeyGenSpec);
    KeyPair ephemeralECKeyPair = ecKeyPairGenerator.generateKeyPair();
    ECPrivateKey ephemeralPrvKey = (ECPrivateKey) ephemeralECKeyPair.getPrivate();
    ECPublicKey ephemeralPubKey = (ECPublicKey) ephemeralECKeyPair.getPublic();
    ECParameterSpec params = ephemeralPubKey.getParams();
    KeyAgreement ecdhKeyAgreement = KeyAgreement.getInstance("ECDH");
    ecdhKeyAgreement.init(ephemeralPrvKey);
    ecdhKeyAgreement.doPhase(senderPubKey, true);
    byte[] sharedSecret = ecdhKeyAgreement.generateSecret();
    byte[] uncompressedEphemeralPubKey = toUncompressedPoint(ephemeralPubKey);
    byte[] aesEncryptResult = aesEncrypt(sharedSecret, msg.getBytes());
    return Base64.getEncoder().encodeToString(
      ByteUtils.concatenate(
        uncompressedEphemeralPubKey,
        aesEncryptResult
      )
    );
  }

  public static String decrypt(ECPrivateKey senderPrvKey, String msg) throws Exception {
    byte[] encryptedBytes = Base64.getDecoder().decode(msg);
    byte[] uncompressedEphemeralPubKeyBytes = Arrays.copyOfRange(
      encryptedBytes,
      0,
      UNCOMPRESSED_PUBLIC_KEY_SIZE
    );
    ECPublicKey ephemeralPubKey = fromUncompressedPoint(uncompressedEphemeralPubKeyBytes);
    KeyAgreement ecdhKeyAgreement = KeyAgreement.getInstance("ECDH");
    ecdhKeyAgreement.init(senderPrvKey);
    ecdhKeyAgreement.doPhase(ephemeralPubKey, true);
    byte[] sharedSecret = ecdhKeyAgreement.generateSecret();
    return new String(
      aesDecrypt(
        sharedSecret,
        Arrays.copyOfRange(
          encryptedBytes,
          UNCOMPRESSED_PUBLIC_KEY_SIZE,
          encryptedBytes.length
        )
      )
    );
  }
}
