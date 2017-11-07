import java.util.*;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServerList implements java.io.Serializable {

    private static final long serialVersionUID = 7600343803563416992L;
    private Hashtable<String, FServ> list = new Hashtable<String, FServ>();

    public synchronized String[] getAllServers() {
        return list.keySet().toArray(new String[0]);
    }

    public synchronized void addServer(String address, PublicKey pub, byte[] signed) {
      String[] parts = address.split(":");

      FServ newServer = new FServ(parts[0], Integer.parseInt(parts[1]), pub, signed);
      list.put(address, newServer);
    }

    public synchronized void deleteServer(String groupName) {
        list.remove(groupName);
    }

    public synchronized boolean checkServer(String address) {
        if(list.containsKey(address))
            return true;
        return false;
    }

    public synchronized PublicKey getPubKey(String address) {
      return list.get(address).getPubKey();
    }
    public synchronized FServ getFServ(String address) {
      return list.get(address);
    }

    /**
     * Inner class to facilitate ServerList functions and features
    */
  }
  class FServ implements java.io.Serializable {

    private static final long serialVersionUID = -6699986336399821572L;

    private PublicKey pub;
    private String ip;
    private int port;
    private byte[] signed;

    // TODO: Store signed pair
    public FServ(String ip, int port, PublicKey pub, byte[] signed) {
      this.ip = ip;
      this.port = port;
      this.pub = pub;
      this.signed = signed;
    }

    public PublicKey getPubKey() {
      return this.pub;
    }

    public String getIP() {
      return this.ip;
    }

    public int getPort() {
      return this.port;
    }

    public byte[] getSigned() {
      return this.signed;
    }
  }     // end KeyPair class
