/** Allows easy access and enumeration of groups and their users */

import java.util.*;

public class GroupList {


    private Hashtable<String, Group> list = new Hashtable<String, Group>();

    public synchronized String[] getAllGroups() {
        return list.keySet().toArray(new String[0]);
    }

    public synchronized void addGroup(String groupName) {
        Group newGroup = new Group();
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

    //TODO: Finish all below
    public synchronized ArrayList<String> getUserGroups(String username) {
        return list.get(username).getGroups();
    }

    public synchronized ArrayList<String> getUserOwnership(String username) {
        return list.get(username).getOwnership();
    }

    public synchronized void addGroup(String user, String groupname) {
        list.get(user).addGroup(groupname);
    }

    public synchronized void removeGroup(String user, String groupname) {
        list.get(user).removeGroup(groupname);
    }

    public synchronized void addOwnership(String user, String groupname) {
        list.get(user).addOwnership(groupname);
    }

    public synchronized void removeOwnership(String user, String groupname) {
        list.get(user).removeOwnership(groupname);
    }
}
