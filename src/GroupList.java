/** Allows easy access and enumeration of groups and their users */




import java.util.*;

public class GroupList {

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

    public synchronized void removeGroup(String groupName) {
        list.remove(groupName);
    }



  class Group implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -6699986336399821572L;
    private ArrayList<String> users;
    private final String owner;

    public Group(String owner) {
      users = new ArrayList<String>();
      this.owner = owner;
      users.add(owner);
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

    public void removeUser(String userName) {
      if(!users.isEmpty()) {
        if(users.contains(userName)) {
          users.remove(users.indexOf(userName));
        }
      }
    }

  }     // end Group class
}
