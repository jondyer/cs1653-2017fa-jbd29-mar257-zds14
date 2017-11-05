/* This thread does all the work. It communicates with the client through Envelopes.*/
 
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.List;
import java.util.*;
import javax.crypto.*;
import java.security.*;

public class TrentThread extends Thread {
  private final Socket socket;
  private TrentServer my_ts;

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

        if(e.getMessage().equals("CSERV")) {//Client wants to create a server
          if (e.getObjContents().size() < 1)
            response = new Envelope("FAIL-BADCONTENTS");
          else {
              if (e.getObjContents().get(0) == null)
                response = new Envelope("FAIL-BADKEY");
              else {
              PublicKey pub = (PublicKey)e.getObjContents().get(0); //Extract public key

              if(registerServer(pub))
                response = new Envelope("OK"); //Success
              }
          }
          output.writeObject(response);
        } else if(e.getMessage().equals("DSERV")) {
          // TODO: Delete File Server Control          
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

  private boolean registerServer(PublicKey pub) {
    if(my_ts.serverList == null) return false;
    String address = socket.getInetAddress() + ":" + socket.getPort();
    if (my_ts.serverList.checkServer(address)) return false;
    my_ts.serverList.addServer(address, pub);
    return true;
  }

  // TODO: Remove File Server
}