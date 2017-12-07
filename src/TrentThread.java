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
  private ObjectInputStream input = null;
  private ObjectOutputStream output = null;

  public TrentThread(Socket _socket, TrentServer _ts, Integer strength) {
    this.socket = _socket;
    this.my_ts = _ts;
    try {
      input = new ObjectInputStream(socket.getInputStream());
      output = new ObjectOutputStream(socket.getOutputStream());
      System.out.println(this.socket.getInetAddress() + ":" + this.socket.getPort() + " is doing a puzzle!");
      doPuzzle(strength);
    } catch(Exception e) {
        System.err.println("Error: " + e.getMessage());
        e.printStackTrace(System.err);
    }

  }

  private void doPuzzle(int strength) throws Exception{
    String[] puzzle = SymmetricKeyOps.makePuzzle(strength);
    Envelope resp = new Envelope("OK");
    resp.addObject(strength);
    resp.addObject(puzzle[1]);
    output.writeObject(resp);
    Envelope puzzleEnv = (Envelope)input.readObject();
    if(!puzzle[0].equals((String) puzzleEnv.getObjContents().get(0))) {
      System.out.println("Invalid puzzle solution!");
      socket.close(); //Close the socket
      System.exit(1);
    }
  }

  public void run() {
    boolean proceed = true;

    try {
      //Announces connection and opens object streams
      System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");

      if(this.input == null || this.output == null ){
        input = new ObjectInputStream(socket.getInputStream());
        output = new ObjectOutputStream(socket.getOutputStream());
      }

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

                String ip = registerServer(pub, port);
                if(ip!=null) {
                  response = new Envelope("OK"); //Success
                  response.addObject(ip);
                }
              }
          }
          output.writeObject(response);
        } else if(e.getMessage().equals("DSERV")) {
          // TODO: Delete File Server Control - IGNORE FOR NOW, NOT a REQUIREMENT
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
                  response.addObject(my_ts.serverList.getFServ(address));
                }
              }
          }
          output.writeObject(response);
        } else if(e.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
          socket.close(); //Close the socket
          proceed = false; //End this communication loop
        } else if(e.getMessage().equals("TRENT")) { // GET TRENTS PUBLIC KEY
          response = new Envelope("OK"); // Success
          response.addObject(my_ts.pub);
          output.writeObject(response);
        } else if(e.getMessage().equals("GROUP")) {  // GET GROUPSERVER PUBLIC KEY
          String add = (String) e.getObjContents().get(0);     // get address of desired groupserver
          response = new Envelope("OK"); // Success
          response.addObject(my_ts.serverList.getPubKey(add));  // add the groupserver's public key
          output.writeObject(response);
        } else {
          response = new Envelope("FAIL"); //Server does not understand client request
          output.writeObject(response);
        }
      } while(proceed);
    } catch(EOFException ex){

      }
      catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  private String registerServer(PublicKey pub, int port) {
    if(my_ts.serverList == null) return null;
    String address = socket.getInetAddress() + ":" + port;
    address = address.replace("/", "");
    if (my_ts.serverList.checkServer(address)) return null;

    Security.addProvider(new BouncyCastleProvider());
    Cipher cipherRSA;
    byte[] sigBytes = null;

    try {
      cipherRSA = Cipher.getInstance("RSA", "BC");
      cipherRSA.init(Cipher.ENCRYPT_MODE, my_ts.priv);
      Signature sig = Signature.getInstance("SHA256withRSA", "BC");
      sig.initSign(my_ts.priv, new SecureRandom());

      String toSign = address + ":" + pub;

      // Hash toSign
      MessageDigest hashed = MessageDigest.getInstance("SHA-256", "BC");
      hashed.update(toSign.getBytes());
      byte[] digest = SymmetricKeyOps.hash(toSign);

      sig.update(digest);
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
    return socket.getInetAddress().toString().split("/")[1];
  }

  // TODO: Remove File Server -- EXTRA CREDIT
}
