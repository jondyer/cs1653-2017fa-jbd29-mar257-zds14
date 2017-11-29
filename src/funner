import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class ECDH {

  /**
   * Generates a Public/Private key pair using a 512 Bit Eliptic Curve Diffie-Hellman Algorithm
   * @return [Public/Private Key Pair]
   */
  public static KeyPair generateKeyPair() {
    try {
      Security.addProvider(new BouncyCastleProvider());
      ECNamedCurveParameterSpec paramSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
      KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("ECDH", "BC");
      keyPairGen.initialize(paramSpec);
      KeyPair keyPair = keyPairGen.generateKeyPair();
      return keyPair;
    } catch(NoSuchAlgorithmException ex1){
      ex1.printStackTrace();
    }
    catch(NoSuchProviderException ex2){
      ex2.printStackTrace();
    }
    catch(InvalidAlgorithmParameterException ex3){
      ex3.printStackTrace();
    }
    return null;
  }

  /**
   * Generates a symmetric AES key based on person 1's private key and person 2's public key
   * @param  PublicKey  pubKey        [Second person's public key]
   * @param  PrivateKey privKey       [First person's private key]
   * @return            [Agreed upon AES key]
   */
  public static SecretKey calculateKey(PublicKey pubKey, PrivateKey privKey){
    try {
      Security.addProvider(new BouncyCastleProvider());
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
      keyAgreement.init(privKey);
      keyAgreement.doPhase(pubKey, true);
      SecretKey symmetricKey = keyAgreement.generateSecret("AES");
      return symmetricKey;
    }
    catch(InvalidKeyException ex1) {
      ex1.printStackTrace();
    }
    catch(NoSuchAlgorithmException ex2) {
      ex2.printStackTrace();
    }
    catch(NoSuchProviderException ex3) {
      ex3.printStackTrace();
    }
    return null;
  }
}
