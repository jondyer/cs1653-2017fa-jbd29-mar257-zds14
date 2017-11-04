import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;


public class TrentServer extends Server {

  public static final int SERVER_PORT = 4444;
  public ServerList serverList;

  public TrentServer() {
    super(SERVER_PORT, "Trent");
  }

  public TrentServer(int _port) {
    super(_port, "Trent");
  }

  public void start() {

    String serverFile = "ServerList.bin";
    Scanner console = new Scanner(System.in);
    ObjectInputStream serverStream;

    //This runs a thread that saves the lists on program exit
    Runtime runtime = Runtime.getRuntime();
    runtime.addShutdownHook(new ShutDownListenerT(this));

    //Open user file to get user list
    try {
      FileInputStream fis = new FileInputStream(serverFile);
      serverStream = new ObjectInputStream(fis);
      serverList = (ServerList)serverStream.readObject();
    } catch(FileNotFoundException e) {
      System.out.println("ServerList File Does Not Exist. Creating ServerList...");
      System.out.println("No file servers currently exist.");

      serverList = new ServerList();
    } catch(IOException e) {
      System.out.println("Error reading from ServerList file");
      System.exit(-1);
    } catch(ClassNotFoundException e) {
      System.out.println("Error reading from ServerList file");
      System.exit(-1);
    }

    //Autosave Daemon. Saves lists every 5 minutes
    AutoSaveT aSave = new AutoSaveT(this);
    aSave.setDaemon(true);
    aSave.start();

    //This block listens for connections and creates threads on new connections
    try {

      final ServerSocket serverSock = new ServerSocket(port);

      Socket sock = null;
      TrentThread thread = null;

      while(true) {
        sock = serverSock.accept();
        thread = new TrentThread(sock, this);
        thread.start();
      }
    }
    catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  public void save() {
    ObjectOutputStream serverStream;
    try {
      serverStream = new ObjectOutputStream(new FileOutputStream("ServerList.bin"));
      serverStream.writeObject(serverList);
    }
    catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }
}

//This thread saves the user list
class ShutDownListenerT extends Thread {
  public TrentServer my_ts;

  public ShutDownListenerT (TrentServer _ts) {
    my_ts = _ts;
  }

  public void run() {
    System.out.println("Shutting down server");
    ObjectOutputStream serverStream;
    try {
      serverStream = new ObjectOutputStream(new FileOutputStream("ServerList.bin"));
      serverStream.writeObject(my_ts.serverList);
    } catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }
}

class AutoSaveT extends Thread {
  public TrentServer my_ts;

  public AutoSaveT (TrentServer _ts) {
    my_ts = _ts;
  }

  public void run() {
    do {
      try {
        Thread.sleep(300000); //Save server list every 5 minutes
        System.out.println("Autosave server list...");
        ObjectOutputStream serverStream;
        try {
          serverStream = new ObjectOutputStream(new FileOutputStream("ServerList.bin"));
          serverStream.writeObject(my_ts.serverList);
        }
        catch(Exception e) {
          System.err.println("Error: " + e.getMessage());
          e.printStackTrace(System.err);
        }
      }
      catch(Exception e) {
        System.out.println("Autosave Interrupted");
      }
    } while(true);
  }
}
