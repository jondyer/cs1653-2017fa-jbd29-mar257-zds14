/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.List;
import java.util.*;

public class GroupThread extends Thread {
  private final Socket socket;
  private GroupServer my_gs;

  public GroupThread(Socket _socket, GroupServer _gs) {
    socket = _socket;
    my_gs = _gs;
  }


  // TODO: Encrypt/Decrypt EVERYTHING (AES/GCM/NoPadding)

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

        // TODO: Encrypt partial token & signed hash of partial token identifier with Key Kgb (Bob-Group Server) and sign with group servers private key
        if(message.getMessage().equals("GET")) { //Client wants a token
          String username = (String)message.getObjContents().get(0); //Get the username
          if(username == null) {
            response = new Envelope("FAIL");
            response.addObject(null);
            output.writeObject(response);
          } else if(message.getObjContents().size() > 1) {  // this is for partial tokens
            String groupname = (String)message.getObjContents().get(1);
            UserToken yourToken = createToken(username, groupname); //Create a token with the specified group

            if(yourToken != null)
              //Respond to the client. On error, the client will receive a null token
              response = new Envelope("OK");
            response.addObject(yourToken);
            output.writeObject(response);
          } else {
            UserToken yourToken = createToken(username); //Create a token

            //Respond to the client. On error, the client will receive a null token
            response = new Envelope("OK");
            response.addObject(yourToken);
            output.writeObject(response);
          }
        }
        else if(message.getMessage().equals("CUSER")){ //Client wants to create a user
          if(message.getObjContents().size() < 2)
            response = new Envelope("FAIL");
          else {
            response = new Envelope("FAIL");

            if(message.getObjContents().get(0) != null) {
              if(message.getObjContents().get(1) != null) {
                String username = (String)message.getObjContents().get(0); //Extract the username
                String password = (String)message.getObjContents().get(1); //Extract the password
                UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

                if(createUser(username, password, yourToken)){
                  response = new Envelope("OK"); //Success
                }
              }
            }
          }
          output.writeObject(response);
        } else if(message.getMessage().equals("DUSER")) { //Client wants to delete a user
          response = new Envelope("FAIL");
          if(message.getObjContents().size() >= 2) {
            if(message.getObjContents().get(0) != null)	{
              if(message.getObjContents().get(1) != null)	{
                String username = (String)message.getObjContents().get(0); //Extract the username
                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                if(deleteUser(username, yourToken))
                  response = new Envelope("OK"); //Success
              }
            }
          }
          output.writeObject(response);
        } else if(message.getMessage().equals("CGROUP")) {//Client wants to create a group
          response = new Envelope("FAIL");
          if(message.getObjContents().size() >= 2) {
            if(message.getObjContents().get(0) != null) {
              if(message.getObjContents().get(1) != null) {
                String groupName = (String) message.getObjContents().get(0); //Extract the group name
                UserToken yourToken = (UserToken) message.getObjContents().get(1); //Extract the token
                if(createGroup(groupName, yourToken))
                  response = new Envelope("OK"); //Success
              }
            }
          }
          output.writeObject(response);
        } else if(message.getMessage().equals("DGROUP")) { //Client wants to delete a group
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 2) {
              if(message.getObjContents().get(0) != null) {
                if(message.getObjContents().get(1) != null) {
                  String groupName = (String)message.getObjContents().get(0); //Extract the groupName
                  UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                  if(deleteGroup(groupName, yourToken)) {
                    response = new Envelope("OK"); //Success
                  }
                }
              }
            }

            output.writeObject(response);
        } else if(message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 2) {
              if(message.getObjContents().get(0) != null) {
                if(message.getObjContents().get(1) != null) {
                  String groupName = (String)message.getObjContents().get(0); //Extract the groupName
                  UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                  List<String> members = listMembers(groupName, yourToken);
                  if(members.size() > 0) {
                    response = new Envelope("OK"); //Success
                    response.addObject(members);
                  }
                }
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("LGROUPS")) { //Client wants a list of members in a group
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 2) {
              if(message.getObjContents().get(0) != null) {
                if(message.getObjContents().get(1) != null) {
                  String userName = (String)message.getObjContents().get(0); //Extract the userName
                  UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                  List<List<String>> resp = listGroups(userName, yourToken);

                  response = new Envelope("OK"); //Success
                  response.addObject(resp);
                }
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("LAGROUPS")) { //Client wants a list of all groups
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 1) {
              if(message.getObjContents().get(0) != null) {
                UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the token

                List<String> groups = listAllGroups(yourToken);
                if (groups != null)
                  response = new Envelope("OK"); //Success
                response.addObject(groups);
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("LAUSERS")) { //Client wants a list of all groups
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 1) {
              if(message.getObjContents().get(0) != null) {
                UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the token

                List<String> users = listAllUsers(yourToken);
                if (users != null)
                  response = new Envelope("OK"); //Success
                response.addObject(users);
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("AUSERTOGROUP")) {//Client wants to add user to a group
          response = new Envelope("FAIL");

          if(message.getObjContents().size() >= 3) {
            if(message.getObjContents().get(0) != null) {
              if(message.getObjContents().get(1) != null) {
                if(message.getObjContents().get(2) != null) {
                String userName = (String)message.getObjContents().get(0); //Extract the username
                String groupName = (String)message.getObjContents().get(1); //Extract the groupName
                UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

                if(addUserToGroup(userName, groupName, yourToken))
                  response = new Envelope("OK"); //Success
                } // missing token
              } // missing groupName
            } // missing userName
          } // missing something!
          output.writeObject(response);
        } else if(message.getMessage().equals("RUSERFROMGROUP")) {//Client wants to remove user from a group
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 3) {
              if(message.getObjContents().get(0) != null) {
                if(message.getObjContents().get(1) != null) {
                  if(message.getObjContents().get(2) != null) {
                  String userName = (String)message.getObjContents().get(0); //Extract the username
                  String groupName = (String)message.getObjContents().get(1); //Extract the groupName
                  UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

                  if(deleteUserFromGroup(userName, groupName, yourToken))
                    response = new Envelope("OK"); //Success
                  } // missing token
                } // missing groupName
              } // missing userName
            } // missing something!
            output.writeObject(response);
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

  //Method to create tokens
  private UserToken createToken(String username) {
    //Check that user exists
    if(my_gs.userList.checkUser(username)) {
      //Issue a new token with server's name, user's name, and user's groups
      UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
      return yourToken;
    } else return null;
  }

  //Method to create tokens
  private UserToken createToken(String username, String groupname) {
    //Check that user exists
    if(my_gs.userList.checkUser(username)) {
      if (!my_gs.groupList.checkGroup(groupname)) return null;
      if (my_gs.groupList.getGroupUsers(groupname).contains(username)) { // check if user is in that group
        //Issue a new token with server's name, user's name, and the single specified group
        UserToken yourToken = new Token(my_gs.name, username, new ArrayList<String>(Arrays.asList(groupname)));
        return yourToken;
      }
    }
    return null;
  }


  //Method to create a user
  private boolean createUser(String username, String password, UserToken yourToken) {
    String requester = yourToken.getSubject();

    //Check if requester exists
    if(my_gs.userList.checkUser(requester)) {
      //Get the user's groups
      ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
      //requester needs to be an administrator
      if(temp.contains("ADMIN")) {
        //Does user already exist?
        if(my_gs.userList.checkUser(username))
          return false; //User already exists
        else {
          my_gs.userList.addUser(username);
          my_gs.userList.setPass(username, password);
          return true;
        }
      }else return false; //requester not an administrator
    } else return false; //requester does not exist
  }

  //Method to delete a user
  private boolean deleteUser(String username, UserToken yourToken) {
    String requester = yourToken.getSubject();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
      //requester needs to be an administer
      if(temp.contains("ADMIN")) {
        //Does user exist?
        if(my_gs.userList.checkUser(username)) {
          //User needs deleted from the groups they belong
          ArrayList<String> deleteFromGroups = new ArrayList<String>();

          //This will produce a hard copy of the list of groups this user belongs
          for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
            deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));


          my_gs.groupList.removeFromGroups(deleteFromGroups, username);

          //If groups are owned, they must be deleted
          ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

          //Make a hard copy of the user's ownership list
          for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
            deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
          }

          //Delete owned groups
          for(int index = 0; index < deleteOwnedGroup.size(); index++) {
            //Use the delete group method. Token must be created for this action
            deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
          }

          //Delete the user from the user list
          my_gs.userList.deleteUser(username);
          return true;

        }else return false; //User does not exist
      }else return false; //requester is not an administer
    }else return false; //requester does not exist
  }

  private boolean createGroup(String groupName, UserToken token) {
    String requester = token.getSubject();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      // Does group already exist?
      if (!my_gs.groupList.checkGroup(groupName)) {
        my_gs.userList.addGroup(requester, groupName);
        my_gs.userList.addOwnership(requester, groupName);
        my_gs.groupList.addGroup(groupName, requester);
        return true;
      }
    }
    return false;
  }

  private boolean deleteGroup(String ownedGroup, UserToken token) {
    String requester = token.getSubject();
    List<String> members = new ArrayList<String>();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      // Checks to make sure the requester is the owner of the group
      if (requester.equals(my_gs.groupList.getGroupOwner(ownedGroup))) {
        members = my_gs.groupList.getGroupUsers(ownedGroup);

        // Removes group affiliation from all previous members
        for (int i = 0; i < members.size(); i++)
          my_gs.userList.removeGroup(members.get(i), ownedGroup);

        // Removes group from list of groups owner owns
        my_gs.userList.removeOwnership(requester, ownedGroup);

        // Removes group from list of groups
        my_gs.groupList.deleteGroup(ownedGroup);

        return true;
      }
    }

    return false;
  }

  /**
   * Lists all members of specified group
   * @param  String    group         Group to be listed
   * @param  UserToken token         Owner of group
   * @return           List of members
   */
  private List<String> listMembers(String group, UserToken token) {
    List<String> members = new ArrayList<String>();
    String requester = token.getSubject();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      // Checks to make sure the requester is the owner of the group
      if (requester.equals(my_gs.groupList.getGroupOwner(group)))
      	members = my_gs.groupList.getGroupUsers(group);
    }

    return members;
  }

  /**
   * Lists all groups belonged to by specified member, as well as groups owned by member
   * @param  String    user          User whose groups we're listing
   * @param  UserToken token         Token of member
   * @return           List of two lists: 1st has membership, 2nd has ownership
   */
  private List<List<String>> listGroups(String user, UserToken token) {
    List<List<String>> groups = new ArrayList<List<String>>();
    String requester = token.getSubject();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      // Checks to make sure the requester is the owner of the token
      if (requester.equals(user)) {
        groups.add(my_gs.userList.getUserGroups(user));
        groups.add(my_gs.userList.getUserOwnership(user));
      }
    }

    return groups;
  }

  /**
   * Returns a list of all groups on the GroupServer (only works for ADMIN)
   * @param  UserToken token         The token of the requester, who must be admin
   * @return           A list of strings which are names of the groups
   */
  private List<String> listAllGroups(UserToken token) {
    String requester = token.getSubject();
    List<String> allGroups = new ArrayList<String>();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      List<String> checkGroups = my_gs.userList.getUserGroups(requester);
      // Checks to make sure the requester is an admin
      if (checkGroups.contains("ADMIN")) {
        Collections.addAll(allGroups, my_gs.groupList.getAllGroups());
      } else return null;
    }

    return allGroups;
  }

  private List<String> listAllUsers(UserToken token) {
    String requester = token.getSubject();
    List<String> allUsers = new ArrayList<String>();

    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      List<String> checkGroups = my_gs.userList.getUserGroups(requester);
      // Checks to make sure the requester is an admin
      if (checkGroups.contains("ADMIN")) {
        Collections.addAll(allUsers, my_gs.userList.getAllUsers());
      } else return null;
    }

    return allUsers;
  }

  /**
   * Adds an extant user to the specified group. Owner of token must also be owner of group.
   * @param  String    user          The user to add to the group.
   * @param  String    group         The group to which the user is added.
   * @param  UserToken token         Token belonging to the group owner.
   * @return           Whether or not the operation was successful.
   */
  private boolean addUserToGroup(String user, String group, UserToken token) {
    String requester = token.getSubject();

    //Check if requester exists
    if(my_gs.userList.checkUser(requester)) {
      //Check if user exists
      if(my_gs.userList.checkUser(user)) {
        // If the requester owns the group
        if (requester.equals(my_gs.groupList.getGroupOwner(group))) {
          // Check if user is already in group
          if (!my_gs.userList.getUserGroups(user).contains(group)) {
            my_gs.userList.addGroup(user, group);
            if (!my_gs.groupList.addToGroup(group, user)) return false;
          return true;
          }
        }  //requester does not own group
      }  //user does not exist
    }  //requester does not exist
    return false;
  }

  private boolean deleteUserFromGroup(String user, String group, UserToken token) {
    String requester = token.getSubject();
    //Does requester exist?
    if(my_gs.userList.checkUser(requester)) {
      // Checks to make sure the requester is the owner of the group
      if (requester.equals(my_gs.groupList.getGroupOwner(group))) {
        //Check if user exists
        if (my_gs.userList.checkUser(user)) {
          my_gs.userList.removeGroup(user, group);
          return my_gs.groupList.removeFromGroup(group, user);
        }
      }
    }

    return false;
  }
}
