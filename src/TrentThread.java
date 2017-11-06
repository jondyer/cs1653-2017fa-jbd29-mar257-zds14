/* This thread does all the work. It communicates with the client through Envelopes.*/

import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.List;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class TrentThread extends Thread {
  private final Socket socket;
  private TrentServer my_ts;
  private SecretKey sessionKey;

  public TrentThread(Socket _socket, TrentServer _ts) {
    socket = _socket;
    my_ts = _ts;
  }

  public void run() {
    boolean proceed = true;

    try {
      //Announces connection and opens object streams
      System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
      final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
      final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

      do {
        Envelope e = (Envelope)input.readObject();
        System.out.println("Request received: " + e.getMessage());
        Envelope response = new Envelope("FAIL");

        if(e.getMessage().equals("CSERV")) { //Client wants to create a server
          if (e.getObjContents().size() < 2)
            response = new Envelope("FAIL-BADCONTENTS");
          else {
              if (e.getObjContents().get(0) == null)
                response = new Envelope("FAIL-BADKEY");
              else {
                PublicKey pub = (PublicKey)e.getObjContents().get(0); //Extract public key
                int port = (int)e.getObjContents().get(1);

                if(registerServer(pub, port))
                  response = new Envelope("OK"); //Success
              }
          }
          output.writeObject(response);
        } else if(e.getMessage().equals("DSERV")) {
          // TODO: Delete File Server Control
        } else if(e.getMessage().equals("GET")) {
          if (e.getObjContents().size() < 1)
            response = new Envelope("FAIL-BADCONTENTS");
          else {
              if(my_ts.serverList == null)
                response = new Envelope("FAIL-BADKEY");
              else {
                String address = (String) e.getObjContents().get(0); //Extract address

                if(my_ts.serverList.checkServer(address)) {
                  response = new Envelope("OK"); // Success
                  response.addObject(my_ts.serverList.getPubKey(address));
                }
              }
          }
          output.writeObject(response);
        } else if(e.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
          socket.close(); //Close the socket
          proceed = false; //End this communication loop
        } else {
          response = new Envelope("FAIL"); //Server does not understand client request
          output.writeObject(response);
        }
      } while(proceed);
    } catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private boolean registerServer(PublicKey pub, int port) {
    if(my_ts.serverList == null) return false;
    String address = socket.getInetAddress() + ":" + port;
    address = address.replace("/", "");
    if (my_ts.serverList.checkServer(address)) return false;

    Security.addProvider(new BouncyCastleProvider());
    Cipher cipherRSA;
    byte[] sigBytes = null;

    try {
      cipherRSA = Cipher.getInstance("RSA", "BC");
      cipherRSA.init(Cipher.ENCRYPT_MODE, my_ts.priv);
      Signature sig = Signature.getInstance("SHA256withRSA", "BC");
      sig.initSign(my_ts.priv, new SecureRandom());

      String toSign = address + ":" + pub;
      sig.update(toSign.getBytes());
      sigBytes = sig.sign();
    } catch(NoSuchAlgorithmException alg) {
      System.out.println(alg.getMessage());
    } catch(NoSuchProviderException prov) {
      System.out.println(prov.getMessage());
    } catch(NoSuchPaddingException pad) {
      System.out.println(pad.getMessage());
    } catch(InvalidKeyException key) {
      System.out.println(key.getMessage());
    } catch(SignatureException sign) {
      System.out.println(sign.getMessage());
    }

    my_ts.serverList.addServer(address, pub, sigBytes);
    return true;
  }

  // TODO: Remove File Server
}
