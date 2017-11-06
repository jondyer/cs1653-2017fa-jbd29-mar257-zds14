import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

import java.lang.Thread;
import java.net.Socket;

import java.security.*;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;


public class TrentClient extends Client {

  private SecretKey sessionKey;
  public byte[] iv = new SecureRandom().generateSeed(16);

  // TODO: Move D-H tools to static class

  /**
  * Default constructor for FileClient class. Runs super's constructor then establishes key with file (thread) server.
  * @return [description]
  */
  public TrentClient(){
    super();
    try{
      keyExchange();
    } catch(Exception e){
      e.printStackTrace();
    }
  }

  /**
  * MUST MUST MUST be run before any other method
  */
  public void keyExchange() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    Security.addProvider(new BouncyCastleProvider());
    Envelope env = new Envelope("KEYX");

    // Generate User's Keypair using Elliptic Curve D-H
    KeyPair clientKeyPair = ECDH.generateKeyPair();
    env.addObject(clientKeyPair.getPublic());
    env.addObject(iv);
    try {
      output.writeObject(env);

      // Get Server's public key and ciphertext
      env = (Envelope)input.readObject();
      PublicKey serverPubKey = (PublicKey) env.getObjContents().get(0);
      byte [] cipherText = (byte []) env.getObjContents().get(1);
      System.out.println(new String(cipherText));

      // Generate Symmetric key from Server Private Key and Client Public Key
      SecretKey sessionKey = ECDH.calculateKey(serverPubKey, clientKeyPair.getPrivate());

      // Decrypt
      Cipher deCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      IvParameterSpec ivSpec = new IvParameterSpec(iv);
      deCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
      byte[] plainText = deCipher.doFinal(cipherText);
      System.out.println(new String(plainText));


    } catch (IOException e1) {
      e1.printStackTrace();
    } catch (ClassNotFoundException e1) {
      e1.printStackTrace();
    }
  }
}
