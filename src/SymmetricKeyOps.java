
/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class SymmetricKeyOps {

  public static final int GCM_IV = 96;    //bit-length of IV
  public static final int GCM_TAG = 128;     //bit-length of verification tag

  public static byte[] encrypt(byte[] plainText, SecretKey agreedKey, GCMParameterSpec spec) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      Cipher symCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      symCipher.init(Cipher.ENCRYPT_MODE, agreedKey, spec);
      byte[] cipherText = symCipher.doFinal(plainText);
      return cipherText;
    } catch(NoSuchAlgorithmException ex1) {
      ex1.printStackTrace();
    }
    catch(InvalidKeyException ex2) {
      ex2.printStackTrace();
    }
    catch(InvalidAlgorithmParameterException ex3) {
      ex3.printStackTrace();
    }
    catch(NoSuchProviderException ex4) {
      ex4.printStackTrace();
    }
    catch(NoSuchPaddingException ex5) {
      ex5.printStackTrace();
    }
    catch(IllegalBlockSizeException ex6) {
      ex6.printStackTrace();
    }
    catch(BadPaddingException ex7) {
      ex7.printStackTrace();
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
    } catch(NoSuchAlgorithmException ex1) {
      ex1.printStackTrace();
    }
    catch(InvalidKeyException ex2) {
      ex2.printStackTrace();
    }
    catch(InvalidAlgorithmParameterException ex3) {
      ex3.printStackTrace();
    }
    catch(NoSuchProviderException ex4) {
      ex4.printStackTrace();
    }
    catch(NoSuchPaddingException ex5) {
      ex5.printStackTrace();
    }
    catch(IllegalBlockSizeException ex6) {
      ex6.printStackTrace();
    }
    catch(BadPaddingException ex7) {
      ex7.printStackTrace();
    }
    return null;
  }

  // TODO: May want to consider just trading IV between user/server and not GCMParameterSpec...
  public static GCMParameterSpec geneatGCMParameterSpec() {
    Security.addProvider(new BouncyCastleProvider());
    // SecureRandom r = SecureRandom.getInstance()
    // final byte[] iv = new byte[GCM_IV];
    // r.nextBytes(iv);
    // ^^^ TODO: This may be the way to do it but it's not correct/IDK
    byte[] iv = new SecureRandom().generateSeed(12); //12 bytes = 96 bits
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG, iv);
    return spec;
  }

}
