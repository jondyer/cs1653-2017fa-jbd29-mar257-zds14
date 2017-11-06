
/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class SymmetricKeyOps {

  public static final int GCM_IV = 12;    //byte-length of IV
  public static final int GCM_TAG = 128;     //bit-length of verification tag

  public static Envelope encrypt(byte[] plainText, SecretKey agreedKey) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      Envelope env = new Envelope();

      // generate the IV
      SecureRandom rand = new SecureRandom();
      final byte[] iv = new byte[GCM_IV];
      rand.nextBytes(iv);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG, iv);

      // actually encrypt
      Cipher symCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      symCipher.init(Cipher.ENCRYPT_MODE, agreedKey, spec);
      byte[] cipherText = symCipher.doFinal(plainText);

      // build the envelope
      env.addObject(iv);
      env.addObject(cipherText);
      return env;

    } catch(Exception e) {
      e.printStackTrace();
    }
    return null;
  }


  public static byte[] encrypt(byte[] plainText, SecretKey agreedKey, GCMParameterSpec spec) {
    try {
      Security.addProvider(new BouncyCastleProvider());

      // actually encrypt
      Cipher symCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      symCipher.init(Cipher.ENCRYPT_MODE, agreedKey, spec);
      byte[] cipherText = symCipher.doFinal(plainText);

      return cipherText;

    } catch(Exception e) {
      e.printStackTrace();
    }
    return null;
  }


  public static byte[] decrypt(byte[] cipherText, SecretKey agreedKey, GCMParameterSpec spec) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      Cipher symCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      symCipher.init(Cipher.DECRYPT_MODE, agreedKey, spec);
      byte[] plainText = symCipher.doFinal(cipherText);
      return plainText;
    } catch(Exception e) {
      e.printStackTrace();
    }
    return null;
  }


  public static GCMParameterSpec getGCMParameterSpec() {
    Security.addProvider(new BouncyCastleProvider());
    SecureRandom r = new SecureRandom();
    byte[] iv = new byte[GCM_IV];
    r.nextBytes(iv);
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG, iv);
    return spec;
  }



  /**
   * Util for converting arbitrary serializable object to byte[]
   * Outline for code from Max @ http://tinyurl.com/69h8l7x
   */
  public static byte[] obj2byte(Object obj) {
    byte[] bytes = null;
    try {
      ByteArrayOutputStream b = new ByteArrayOutputStream();
      ObjectOutputStream o = new ObjectOutputStream(b);
      o.writeObject(obj);
      o.flush();
      o.close();
      b.close();
      bytes = b.toByteArray();

    } catch (Exception e) {
        e.printStackTrace();
      }

      return bytes;
    }

  /**
   * Util for converting arbitrary byte[] to object
   * Outline for code from Max @ http://tinyurl.com/69h8l7x
   */
  public static Object byte2obj(byte[] bytes) {
    Object obj = null;

    try {
      ByteArrayInputStream b = new ByteArrayInputStream(bytes);
      ObjectInputStream o = new ObjectInputStream(b);
      obj = o.readObject();

    } catch (Exception e) {
      e.printStackTrace();
    }

    return obj;
  }
}
