import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;


class EncryptionTest {
  @org.junit.jupiter.api.Test
  void aesEncrypt() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException {
    System.out.println("AES Encrypt");
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    SecretKey key = keyGenerator.generateKey();
    String plaintext = "Hello World";
    System.out.println("Original Text: " + plaintext);
    byte[] cipherText = Encryption.aesEncrypt(key.getEncoded(), plaintext.getBytes());
    System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(cipherText).length());
  }

  @org.junit.jupiter.api.Test
  void aesDecrypt() throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    System.out.println("AES Decrypt");
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    SecretKey key = keyGenerator.generateKey();
    String plaintext = "hello world ~~~~~~~~~~~~~~~~~~~~~~";
    System.out.println("Original Text: " + plaintext);
    byte[] cipherText = Encryption.aesEncrypt(key.getEncoded(), plaintext.getBytes());
    System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(cipherText));
    byte[] decrypt = Encryption.aesDecrypt(key.getEncoded(), cipherText);
    System.out.println("Decrypted Text: " + new String(decrypt));
  }

  @org.junit.jupiter.api.Test
  void encrypt() throws Exception {
    System.out.println("Encrypt");
    String certFileName = "materials/cert.pem";
    ECPublicKey senderPubKey = Encryption.readPubKeyFromPemFile(certFileName);
    String msg = "hello world ~~~~~~~~~~~~~~~~~~~~~~";
    String encrypted = Encryption.encrypt(senderPubKey, msg);
    System.out.println("Encrypted Text: " + encrypted);
  }

  @org.junit.jupiter.api.Test
  void decrypt() throws Exception {
    System.out.println("Decrypt");
    String certFileName =  "materials/cert.pem";
    ECPublicKey senderPubKey = Encryption.readPubKeyFromPemFile(certFileName);
    String msg = "hello world ~~~~~~~~~~~~~~~~~~~~~~";
    String encrypted = Encryption.encrypt(senderPubKey, msg);
    String keyFileName = "materials/key.pem";
    ECPrivateKey senderPrvKey = Encryption.readPrvKeyFromPemFile(keyFileName);
    String decrypted = Encryption.decrypt(senderPrvKey, encrypted);
    System.out.println("Decrypted Text: " + decrypted);
  }

  @org.junit.jupiter.api.Test
  void verifyNodeResult() throws Exception {
    System.out.println("Verify Node Result");
    String encrypted = "BAql7wpV+l72smxw9AzZkxkNWqpcgMwLQQYFnMi2f71pvxGm2TXGPc2LSfARzBe29i9+Az7sYPYp9fAkABf4YZHgsDcaMta7582TxI04ub3fil2wEQBKQPedYmtYoymbzrehuYo2oRSPNoMgFCQzLl6vX42KOdlmmuCtGXWP9K5wcLo=";
    String keyFileName = "materials/key.pem";
    ECPrivateKey senderPrvKey = Encryption.readPrvKeyFromPemFile(keyFileName);
    String decrypted = Encryption.decrypt(senderPrvKey, encrypted);
    System.out.println("Decrypted Text: " + decrypted);
  }
}