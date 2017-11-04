/* This thread does all the work. It communicates with the client through Envelopes.
 */
 
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.List;
import java.util.*;

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
        Envelope message = (Envelope)input.readObject();
        System.out.println("Request received: " + message.getMessage());
        Envelope response = new Envelope("FAIL");

        if(message.getMessage().equals("CSERV")) {//Client wants to create a server
          // TODO: Create File Server Control
        } else if(message.getMessage().equals("DSERV")) {
          // TODO: Delete File Server Control          
        } else if(message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
          socket.close(); //Close the socket
          proceed = false; //End this communication loop
        } else {
          response = new Envelope("FAIL"); //Server does not understand client request
          output.writeObject(response);
        }
      } while(proceed);
    }
    catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  // TODO: Create File Server

  // TODO: Delete File Server
}