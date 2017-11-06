import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

import java.lang.Thread;
import java.net.Socket;

import java.security.*;
import java.security.spec.*;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;


public class TrentClient extends Client {

  private SecretKey sessionKey;
  public byte[] iv = new SecureRandom().generateSeed(16);


  public PublicKey getPublicKey(String ipaddress, int port) throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    // Pass Trent address of file server we want to connect to
    Envelope env = new Envelope("GET");
    String address = ipaddress + ":" + port;
    env.addObject(address);
    output.writeObject(env);

    // Recover FSx's Public Key from returned bytes
    env = (Envelope)input.readObject();
    PublicKey fileServerPublicKey = (PublicKey) env.getObjContents().get(0);
    return fileServerPublicKey;
  }
}
