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

  @SuppressWarnings("all")
  public PublicKey getPublicKey(String ipaddress, int port, PublicKey trentPubKey) throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    // Pass Trent address of server we want to connect to
    Envelope env = new Envelope("GET");
    String address = ipaddress + ":" + port;
    env.addObject(address);
    output.writeObject(env);

    // Recover fields from FServ Object
    env = (Envelope)input.readObject();
    FServ returned = (FServ) env.getObjContents().get(0);
    PublicKey fileServerPublicKey = returned.getPubKey();
    String ip = returned.getIP();
    int returnedPort = returned.getPort();
    byte[] signed = returned.getSigned();

    String toHash = ip +  ":" + returnedPort + ":" + fileServerPublicKey;

    // Hash plainKey to update signature object to verify trent
    byte[] digest = SymmetricKeyOps.hash(toHash);

    // Verify FSx's Public Key from returned bytes
    Signature pubSig = Signature.getInstance("SHA256withRSA", "BC");
    pubSig.initVerify(trentPubKey);
    pubSig.update(digest);
    boolean match = pubSig.verify(signed);

    if(match)
      return fileServerPublicKey;
    System.out.println("Error verifing Trent's public key");
    return null;
  }

  public PublicKey getTrentPub() throws Exception {
    Envelope env = new Envelope("TRENT");
    output.writeObject(env);
    env = (Envelope)input.readObject();
    return (PublicKey) env.getObjContents().get(0);
  }
}
