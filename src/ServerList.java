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

    public synchronized void addServer(String address, PublicKey pub) {
      String[] parts = address.split(":");

      FServ newServer = new FServ(parts[0], Integer.parseInt(parts[1]), pub);
      list.put(address, newServer);
    }

    public synchronized void addServer(String ip, int port, PublicKey pub) {
      FServ newServer = new FServ(ip, port, pub);
      list.put((ip + ":" + port), newServer);
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

    /**
     * Inner class to facilitate ServerList functions and features
    */
  class FServ implements java.io.Serializable {

    private static final long serialVersionUID = -6699986336399821572L;

    private PublicKey pub;
    public String ip;
    public int port;

    public FServ(String ip, int port, PublicKey pub) {
      this.ip = ip;
      this.port = port;
      this.pub = pub;
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
  }     // end KeyPair class
}
