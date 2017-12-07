/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */


import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.math.BigInteger;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

public class GroupServer extends Server {


  public static final int SERVER_PORT = 8765;
  public static int TRENT_PORT = 4444;
  public static String TRENT_IP = "127.0.0.1";
  public UserList userList;
  public GroupList groupList;

  private static final BigInteger g_1024 = new BigInteger(1, Hex.decode("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
        + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
        + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
        + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
        + "FD5138FE8376435B9FC61D2FC0EB06E3"));
  private static final BigInteger N_1024 = new BigInteger(1, Hex.decode("000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));

  public GroupServer() {
    super(SERVER_PORT, "ALPHA");
  }

  public GroupServer(int _port) {
    super(_port, "ALPHA");
  }

  public void start(String[] args) {
    // Overwrote server.start() because if no user file exists, initial admin account needs to be created
    if(args.length >= 2)      // just the Trent IP
      TRENT_IP = args[1];
    if(args.length >= 3)      // IP and port
      TRENT_PORT = Integer.parseInt(args[2]);

    registerServer(TRENT_IP, TRENT_PORT);

    String userFile = "UserList.bin";
    String groupFile = "GroupList.bin";
    Scanner console = new Scanner(System.in);
    ObjectInputStream userStream;
    ObjectInputStream groupStream;

    //This runs a thread that saves the lists on program exit
    Runtime runtime = Runtime.getRuntime();
    runtime.addShutdownHook(new ShutDownListener(this));

    //Open user file to get user list
    try {
      FileInputStream fis = new FileInputStream(userFile);
      userStream = new ObjectInputStream(fis);
      userList = (UserList)userStream.readObject();

      FileInputStream fis1 = new FileInputStream(groupFile);
      groupStream = new ObjectInputStream(fis1);
      groupList = (GroupList)groupStream.readObject();
    } catch(FileNotFoundException e) {
      System.out.println("UserList File Does Not Exist. Creating UserList...");
      System.out.println("No users currently exist. Your account will be the administrator.");
      System.out.print("Enter your username: ");
      String username = console.next();

      boolean match = false;
      String pw1 = "";
      String pw2;

      while(!match) {
        System.out.print("Enter a password for this account: ");
        pw1 = console.next();
        System.out.print("Please enter the password again to confirm: ");
        pw2 = console.next();
        if(pw1.equals(pw2)) match = true;
      }

      //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
      userList = new UserList();
      userList.addUser(username);
      userList.addGroup(username, "ADMIN");
      userList.addOwnership(username, "ADMIN");

      SecureRandom random = new SecureRandom();
      byte[] s = new byte[32];
      random.nextBytes(s);

      BigInteger x = SRP6Util.calculateX(new SHA256Digest(), N_1024, s, username.getBytes(), pw1.getBytes());
      userList.setPass(username, s, g_1024.modPow(x, N_1024));

      groupList = new GroupList();
      groupList.addGroup("ADMIN", username);
    } catch(IOException e) {
      System.out.println("Error reading from UserList file");
      System.exit(-1);
    } catch(ClassNotFoundException e) {
      System.out.println("Error reading from UserList file");
      System.exit(-1);
    }

    //Autosave Daemon. Saves lists every 5 minutes
    AutoSave aSave = new AutoSave(this);
    aSave.setDaemon(true);
    aSave.start();

    //This block listens for connections and creates threads on new connections
    try {

      final ServerSocket serverSock = new ServerSocket(port);

      Socket sock = null;
      GroupThread thread = null;

      while(true) {
        sock = serverSock.accept();
        thread = new GroupThread(sock, this, 1);
        thread.start();
      }
    }
    catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  protected byte[] signAndHash(String text) {
    Security.addProvider(new BouncyCastleProvider());
    Cipher cipherRSA;
    Signature sig;
    byte [] signed = null;

    try{
      // Hash
      MessageDigest hashed = MessageDigest.getInstance("SHA-256", "BC");
			hashed.update(text.getBytes()); // Change this to "UTF-16" if needed
			byte[] hash = hashed.digest();

      // Sign
      cipherRSA = Cipher.getInstance("RSA", "BC");
      cipherRSA.init(Cipher.ENCRYPT_MODE, priv);
      sig = Signature.getInstance("SHA256withRSA", "BC");
      sig.initSign(priv, new SecureRandom());

      sig.update(hash);
      signed = sig.sign();
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

    return signed;
  }

  public void save() {
    ObjectOutputStream userStream;
    ObjectOutputStream groupStream;
    try {
      userStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
      groupStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));

      userStream.writeObject(userList);
      groupStream.writeObject(groupList);
    }
    catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }
}

//This thread saves the user list
class ShutDownListener extends Thread {
  public GroupServer my_gs;

  public ShutDownListener (GroupServer _gs) {
    my_gs = _gs;
  }

  public void run() {
    System.out.println("Shutting down server");
    ObjectOutputStream userStream;
    ObjectOutputStream groupStream;
    try {
      userStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
      groupStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));

      userStream.writeObject(my_gs.userList);
      groupStream.writeObject(my_gs.groupList);

    } catch(Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }
}

class AutoSave extends Thread {
  public GroupServer my_gs;

  public AutoSave (GroupServer _gs) {
    my_gs = _gs;
  }

  public void run() {
    do {
      try {
        Thread.sleep(300000); //Save group and user lists every 5 minutes
        System.out.println("Autosave group and user lists...");
        ObjectOutputStream userStream;
        ObjectOutputStream groupStream;
        try {
          userStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
          groupStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));

          userStream.writeObject(my_gs.userList);
          groupStream.writeObject(my_gs.groupList);
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
