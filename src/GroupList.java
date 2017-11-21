/** Allows easy access and enumeration of groups and their users */

import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

public class GroupList implements java.io.Serializable {

    private static final long serialVersionUID = 7600343803563416992L;
    private Hashtable<String, Group> list = new Hashtable<String, Group>();

    public synchronized String[] getAllGroups() {
        return list.keySet().toArray(new String[0]);
    }

    public synchronized void addGroup(String groupName, String owner) {
        Group newGroup = new Group(owner);
        list.put(groupName, newGroup);
    }

    public synchronized void deleteGroup(String groupName) {
        list.remove(groupName);
    }

    public synchronized boolean checkGroup(String groupName) {
        if(list.containsKey(groupName))
            return true;
        return false;
    }

    public synchronized String getGroupOwner(String groupName) {
        return list.get(groupName).getOwner();
    }

    public synchronized ArrayList<String> getGroupUsers(String groupName) {
      Group group = list.get(groupName);
      ArrayList<String> guList = new ArrayList<String>(group.getUsers());
      return guList;
    }

    public synchronized boolean addToGroup(String group, String user) {
      if (checkGroup(group)) {
        list.get(group).addUser(user);
        return true;
      }
      return false;
    }

    public synchronized boolean removeFromGroup(String group, String user) {
      return list.get(group).removeUser(user);
    }

    public synchronized boolean removeFromGroups(ArrayList<String> groups, String user) {
      for (int i = 0; i < groups.size(); i++) {
        if (!removeFromGroup(groups.get(i), user)) {
          return false;
        }
      }
      return true;
    }

    public synchronized SecretKey getKey(String group) {
      return list.get(group).getKey();
    }

    public synchronized int getHashNum(String group) {
      return list.get(group).getHashNum();
    }

    public synchronized void updateKey(String group) {
      list.get(group).updateKey();
    }


    /**
     * Inner class to facilitate GroupList functions and features
    */
  class Group implements java.io.Serializable {

    private static final long serialVersionUID = -6699986336399821572L;
    private ArrayList<String> users;
    private final String owner;
    private SecretKey baseKey, currKey;
    private static final int MAX_HASH = 1000;
    private int currentHashNum = MAX_HASH + 1;

    public Group(String owner) {
      users = new ArrayList<String>();
      this.owner = owner;
      users.add(owner);
      genKey();
    }

    public ArrayList<String> getUsers() {
      return users;
    }

    public String getOwner() {
      return owner;
    }

    public void addUser(String userName) {
      users.add(userName);
    }

    public boolean removeUser(String userName) {
      if(!users.isEmpty()) {
        if(users.contains(userName)) {
          users.remove(users.indexOf(userName));
          return true;
        }
      }
      return false;
    }

    private void genKey() {
      try{
        KeyGenerator keyGenAES = KeyGenerator.getInstance("AES", "BC");
        keyGenAES.init(128);

        baseKey = keyGenAES.generateKey();
        updateKey();
      } catch(NoSuchAlgorithmException alg) {
        System.out.println(alg.getMessage());
      } catch(NoSuchProviderException prov) {
        System.out.println(prov.getMessage());
      }
    }

    public void updateKey() {
      byte [] hash = SymmetricKeyOps.hash(SymmetricKeyOps.obj2byte(baseKey));
      currentHashNum--;
      for (int i = 1; i < currentHashNum; i++) {
        hash = SymmetricKeyOps.hash(hash);
      }
      currKey = new SecretKeySpec(hash, 0, 16, "AES");
    }

    public SecretKey getKey() {
      return currKey;
    }

    public int getHashNum() {
      return currentHashNum;
    }

  }     // end Group class
}
