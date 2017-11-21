/**
 * This class does all the things.
 * Basic CLI for performing file and group operations.
 */
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Driver Class
public class RunClientApp {
  public static void main(String [] args) throws Exception {
    ClientApp newApp;
    if (args.length == 0)
      newApp = new ClientApp();
    else
      newApp = new ClientApp(args);
  }
}

class ClientApp {

  private int GROUP_PORT = 8765;
  private String groupHost = "127.0.0.1";
  private int FILE_PORT = 4321;
  private String fileHost = "127.0.0.1";
  private int TRENT_PORT = 4444;
  private String trentHost = "127.0.0.1";

  Scanner console = new Scanner(System.in);
  TrentClient trentClient = new TrentClient();
  GroupClient groupClient = new GroupClient();
  FileClient fileClient = new FileClient();
  public ClientApp() throws Exception {
    // INTERACTIVE SETUP
    String temp;
    int temport;
    System.out.print("Please enter an IP address for Trent, or leave blank for default (localhost) >> ");
    temp = console.nextLine();
    if(!temp.equals(""))
      trentHost = temp.trim();

    System.out.print("Please enter a port for Trent, or leave blank for default (4444) >> ");
    temp = console.nextLine();
    if(!temp.equals("")) {
      temport = Integer.parseInt(temp.trim());
      TRENT_PORT = temport;
    }

    System.out.print("Please enter an IP address for GroupServer, or leave blank for default (localhost) >> ");
    temp = console.nextLine();
    if(!temp.equals(""))
      groupHost = temp.trim();

    System.out.print("Please enter a port for GroupServer, or leave blank for default (8765) >> ");
    temp = console.nextLine();
    if(!temp.equals("")) {
      temport = Integer.parseInt(temp.trim());
      GROUP_PORT = temport;
    }

    System.out.print("Please enter an IP address for FileServer, or leave blank for default (localhost) >> ");
    temp = console.nextLine();
    if(!temp.equals(""))
      fileHost = temp.trim();

    System.out.print("Please enter a port for FileServer, or leave blank for default (4321) >> ");
    temp = console.nextLine();
    if(!temp.equals("")) {
      temport = Integer.parseInt(temp.trim());
      FILE_PORT = temport;
    }

    // END INTERACTIVE SETUP

    run();
  }

  public ClientApp(String [] args) throws Exception {
    if (args.length == 1)
      FILE_PORT = Integer.parseInt(args[0]);
    else if (args.length == 2) {
      FILE_PORT = Integer.parseInt(args[0]);
      GROUP_PORT = Integer.parseInt(args[1]);
    } else if (args.length == 3) {
      FILE_PORT = Integer.parseInt(args[0]);
      GROUP_PORT = Integer.parseInt(args[1]);
      TRENT_PORT = Integer.parseInt(args[3]);
    }
     if (args.length == 4) {
      fileHost = args[0];
      FILE_PORT = Integer.parseInt(args[1]);
      groupHost = args[2];
      GROUP_PORT = Integer.parseInt(args[3]);
    } else if (args.length == 6) {
      fileHost = args[0];
      FILE_PORT = Integer.parseInt(args[1]);
      groupHost = args[2];
      GROUP_PORT = Integer.parseInt(args[3]);
      trentHost = args[4];
      TRENT_PORT = Integer.parseInt(args[5]);
    }
    run();
  }

  public void run() throws Exception {
    Security.addProvider(new BouncyCastleProvider());


    // Connect to Servers
    groupClient.connect(groupHost, GROUP_PORT);
    trentClient.connect(trentHost, TRENT_PORT);
    PublicKey trentPublicKey = trentClient.getTrentPub(); // Arbitrary way to get Trent's public key - Dr. Lee said it was a fair assumption that everyone can know Trent's public key
    PublicKey groupServerPublicKey = trentClient.getPublicKey(groupHost, GROUP_PORT, trentPublicKey); // Get group server's public key
    groupClient.setGroupPubKey(groupServerPublicKey);
    fileClient.setGroupPubKey(groupServerPublicKey);
    PublicKey fileServerPublicKey = trentClient.getPublicKey(fileHost, FILE_PORT, trentPublicKey); // Get selected File Server's public key from Trent to later use for verification
    fileClient.connect(fileHost, FILE_PORT);
    fileClient.keyExchange(fileServerPublicKey);

    // TODO: Give GroupThread info about File Server's address so it can be included on tokens

    // Get Username & Token
    System.out.print("Welcome! Please login with your username >> ");
    String username = console.next();
    System.out.print("Please enter your password >> ");
    String pw = console.next();

    if (!groupClient.clientSRP(username, pw)) {
      System.out.println("SRP verification has failed...");
      System.out.println("Exiting now...");
      return;
    }


    UserToken token = groupClient.getToken(username);

    // Check to make sure token exists
    if(token == null) {
      System.out.println("Account not valid.");
      System.exit(0);
    }
    boolean selectGroup = true;
    while(selectGroup){
      // Check if user has admin privileges
      boolean isAdmin = false;
      if(groupClient.isAdmin(username)) {
        System.out.print("Are you performing administrative operations? (y/n) >> ");
        String response = console.next();

        // Wanna be a BIG boy?
        if(response.equals("y") || response.equals("Y"))
          isAdmin = true;
      }

      // Get groups belonged to
      List<List<String>> groupLists = groupClient.listGroups(username, token);
      ArrayList<String> groupsBelongedTo = (ArrayList<String>) groupLists.get(0);
      ArrayList<String> groupsOwned = (ArrayList<String>) groupLists.get(1);

      // List groups
      System.out.println("These are the groups you belong to: ");
      for(int i=0; i<groupsBelongedTo.size(); i++)
      System.out.println(i + ") " + groupsBelongedTo.get(i));

      // TODO: Support selection of multiple groups at once for operation
      // Select a group
      System.out.print("Please select a group you wish to access ('q' to quit, 'c' to create a new group) >> ");
      String selection = console.next();
      if(selection.equals("q")) {
        selectGroup = false;
        break;
      } else if(selection.equals("c")) {
        createGroup(token);
        //updateConnection(groupClient, groupHost, GROUP_PORT);
        continue;
      // } else if(selection.equals("r")) {
      //   updateConnection(groupClient, groupHost, GROUP_PORT);
      //   updateConnection(fileClient, fileHost, FILE_PORT);
      //   continue;
      }
      String choice = groupsBelongedTo.get(Integer.parseInt(selection));
      boolean isOwner = false;

      // Check if owner of selected group
      if(groupsOwned.contains(choice) && !isAdmin) {
        System.out.print("Would you to perform owner actions? (y/n) >> ");
        String response = console.next();

        // Wanna be a big boy?
        if(response.equals("y") || response.equals("Y"))
          isOwner = true;
      } else if (groupsOwned.contains(choice) && isAdmin)
          isOwner = true;

      // update token --> retrieve new partial token!!! + give signed hash of that partial token to FileClient
      token = groupClient.getToken(username,choice);
      fileClient.setSignedHash(groupClient.getSignedHash());  // After groupClient has token, give GroupServer-signed hash of token identifier to file client to

      // Compile List of privileges for each level of usage
      ArrayList<String> adminList = new ArrayList<String>();
      adminList.add("Create user");
      adminList.add("Delete user");
      adminList.add("List all groups");
      adminList.add("List all users");
      ArrayList<String> ownerList = new ArrayList<String>();
      ownerList.add("List members of a group");
      ownerList.add("Add user to group");
      ownerList.add("Remove user from group");
      ownerList.add("Delete group");
      ArrayList<String> memberList = new ArrayList<String>();
      memberList.add("List files");
      memberList.add("Upload files");
      memberList.add("Download files");
      memberList.add("Delete files");
      memberList.add("Create a group");

      boolean doAgain = true;
      while(doAgain) {   // main menu while loop
        // Menu, show selected group and access level
        System.out.println("\n\n----MENU----");
        System.out.println("Selected Group: " + choice);

        if(isAdmin) System.out.println("Operating as Admin");
        else if(isOwner) System.out.println("Operating as Owner");
        else System.out.println("Operating as User");

        System.out.println("\n");

        // List options for each privilege level
        // ADMIN
        if(isAdmin){
          System.out.println("Admin Ops:");
          for(int i = 0; i < adminList.size(); i++)
            System.out.println("a" + i + ") " + adminList.get(i));
          System.out.println("\n");
        }
        // OWNER
        if(isOwner){
          System.out.println("Owner Ops:");
          for(int i = 0; i < ownerList.size(); i++)
            System.out.println("o" + i + ") " + ownerList.get(i));
          System.out.println("\n");
        }
        // USER (options are always there for user level)
        System.out.println("User Ops:");
        for(int i = 0; i < memberList.size(); i++)
          System.out.println(i + ") " + memberList.get(i));
        System.out.println("\n");

        System.out.print("Please select an option ('q' to select a different group) >> ");
        String response = console.next();
        switch(response) {

          // ADMIN ACTIONS -----------------
          // Create user
          case "a0":
            if(isAdmin) createUser(token);
            //updateConnection(groupClient, groupHost, GROUP_PORT);
            //updateConnection(fileClient, fileHost, FILE_PORT);
            break;

          // Delete user
          case "a1":
            if(isAdmin) deleteUser(token);
            //updateConnection(groupClient, groupHost, GROUP_PORT);
            //updateConnection(fileClient, fileHost, FILE_PORT);
            break;

          case "a2":
            if(isAdmin) listAllGroups(token);
            break;

          case "a3":
            if(isAdmin) listAllUsers(token);
            break;


          // OWNER ACTIONS -----------------
          // List members of a group
          case "o0":
            if(isOwner) listMembers(choice, token);
            break;

          // Add user to a group
          case "o1":
            if(isOwner) addUserToGroup(choice, token);
            //updateConnection(groupClient, groupHost, GROUP_PORT);
            break;

          // Remove user from a group
          case "o2":
            if(isOwner) removeUserFromGroup(choice, token);
            //updateConnection(groupClient, groupHost, GROUP_PORT);
            break;

          // Delete group
          case "o3":
            if(isOwner) deleteGroup(choice, token);
            //updateConnection(groupClient, groupHost, GROUP_PORT);
            //updateConnection(fileClient, fileHost, FILE_PORT);
            doAgain = false;
            break;


          // USER ACTIONS -----------------
          // List files
          case "0":
            listFiles(token);
            break;

          // Upload files
          case "1":
            uploadFile(choice, token);
            break;

          // Download files
          case "2":
            downloadFile(token);
            break;

          // Delete files
          case "3":
            // Delete files
            deleteFile(token);
            break;

          // Create a group=
          case "4":
            // Create a group
            createGroup(token);
            //updateConnection(groupClient, groupHost, GROUP_PORT);
            //updateConnection(fileClient, fileHost, FILE_PORT);
            break;

          //quit
          case "q":
            doAgain = false;
            break;

          //refresh
          // case "r":
          //   updateConnection(groupClient, groupHost, GROUP_PORT);
          //   updateConnection(fileClient, fileHost, FILE_PORT);
          //   break;

          // Invalid choice
          default:
            System.out.println("Not a valid menu choice");
            break;
        } // switch response
      } // end doAgain
    } // end selectGroup
    groupClient.disconnect();
    fileClient.disconnect();
  } // end run()

  /**
  * Creates a user in the system (ADMIN ONLY)
  * @param  UserToken myToken       Token of the administrator
  * @return           Success of operation
  */
  private boolean createUser(UserToken myToken) {
    System.out.print("Username of the person you wish to create? >> ");
    String username = console.next();

    boolean match = false;
    String pw1 = "";
    String pw2;

    while(!match) {
      System.out.print("Password for this account? >> ");
      pw1 = console.next();
      System.out.print("Please enter the password again to confirm >> ");
      pw2 = console.next();
      if(pw1.equals(pw2)) match = true;
    }


    boolean status = groupClient.createUser(username, pw1, myToken);
    if(status)
      System.out.println("Successfully created user '" + username + "'\n");
    else
      System.out.println("Failed to create user '" + username + "'\n");
    return status;
  }

  /**
  * Deletes a user from the system (ADMIN ONLY)
  * @param  UserToken myToken       Token of the administrator
  * @return           Success of operation
  */
  private boolean deleteUser(UserToken myToken) {
    System.out.print("Username of the person you wish to delete? >> ");
    String username = console.next();
    boolean status = false;
    if(!username.equals(myToken.getSubject()))
      status = groupClient.deleteUser(username, myToken);
    if(status)
      System.out.println("Successfully deleted user '" + username + "'\n");
    else
      System.out.println("Failed to delete user '" + username + "'\n");
    return status;
  }

    /**
     * Lists all groups on the group server (ADMIN ONLY)
     * @param UserToken token Requester's token (must be admin)
     */
    private void listAllGroups(UserToken token) {
      List<String> groupList = groupClient.listAllGroups(token);
      System.out.println("\nAll groups on group server");
      for(String s : groupList)
        System.out.println("- " + s);
    }


    private void listAllUsers(UserToken token) {
      List<String> userList = groupClient.listAllUsers(token);
      System.out.println("\nAll users on group server");
      for(String s : userList)
        System.out.println("- " + s);
    }



  /**
   * Lists all members of a group.
   * @param  String    group         Name of the group to list members for
   * @param  UserToken myToken       Token of the owner of the group
   */
  private void listMembers(String group, UserToken myToken) {
    ArrayList<String> members = (ArrayList<String>) groupClient.listMembers(group, myToken);
    System.out.println("Members of '" + group + "'");
    for(String member : members)
      System.out.println("- " + member);
  }

  /**
   * Adds an existing user to a specfied group.
   * @param  String    group         Name of group to add user to
   * @param  UserToken myToken       Token of the owner of the group
   * @return           Success of operation
   */
  private boolean addUserToGroup(String group, UserToken myToken) {
    System.out.print("Username of the person you wish to add to '" + group +  "'? >> ");
    String username = console.next();
    boolean status = groupClient.addUserToGroup(username, group, myToken);
    if(status)
      System.out.println("Successfully added user '" + username + "' to '"+ group + "'\n");
    else
      System.out.println("Failed to add user '" + username + "'\n");
    return status;
  }

  /**
   * Removes an existing user from a specified group.
   * @param  String    group         Name of group to remove user from
   * @param  UserToken myToken       Token of the owner of the group
   * @return           Success of operation
   */
  private boolean removeUserFromGroup(String group, UserToken myToken) {
    System.out.print("Username of the person you wish to remove from '" + group +  "'? >> ");
    String username = console.next();
    if(username.equals(myToken.getSubject())) {
      System.out.println("You can't remove yourself from the group!");
      return false;
    }
    boolean status = groupClient.deleteUserFromGroup(username, group, myToken);
    if(status)
      System.out.println("Successfully removed user '" + username + "' from '"+ group + "'\n");
    else
      System.out.println("Failed to remove user '" + username + "'\n");
    return status;
  }

  /**
   * Removes all user(s) from selected group and deletes the group
   * @param  String    group         Selected group to delete
   * @param  UserToken myToken       Token of the owner of the group to be deleted
   * @return           Success of operation
   */
  private boolean deleteGroup(String group, UserToken myToken) {
    System.out.print("Are you sure you wish to delete group '" + group + "' and remove all users from it? (y/n) >> ");
    String choice = console.next();
    boolean status = false;
    if(choice.equals("Y") || choice.equals("y")) {
      if(!group.equals("ADMIN"))
        status = groupClient.deleteGroup(group, myToken);
      if(status)
        System.out.println("Successfully deleted group '" + group + "'\n");
      else
        System.out.println("Failed to delete group '" + group + "'\n");
      return status;
    }
    return false;
  }

  /**
   * Prints out all files available to the user currently logged in
   * @param UserToken myToken Token of the user whose files are to be printed
   */
  private void listFiles(UserToken myToken) {
    ArrayList<String> userFiles = (ArrayList<String>) fileClient.listFiles(myToken);
    System.out.println("\nFiles for user '" + myToken.getSubject() + "'");
    for(String s : userFiles)
      System.out.println("- " + s);
  }

  /**
   * Uploads a new file to the currently selected group.
   * @param  String    group         Group for file to be uploaded to
   * @param  UserToken myToken       Token of the user uploading the file
   * @return           Success of operation.
   */
  private boolean uploadFile(String group, UserToken myToken) {
    // Get file to be uploaded
    System.out.print("Path of the source file? >> ");
    String sourceFile = console.next();

    // Check if file exists
    File test = new File(sourceFile);
    if(!test.exists()) {
      System.out.println("Source file could not be found.");
      return false;
    }

    // Pick new filename
    System.out.print("Name of the destination file? >> ");
    String destinationFilename = console.next();
    // TODO: Encrypt file before upload
    boolean status = fileClient.upload(sourceFile, destinationFilename, group, myToken);
    if(status)
      System.out.println("Successfully uploaded file '" + sourceFile + "'\n");
    else
      System.out.println("Failed to upload '" + sourceFile + "'\n");
    return status;
  }

  /**
   * Downloads a specified file to a specified location/name.
   * @param  UserToken myToken       Token of the user downloading the file
   * @return           Sucess of operation.
   */
  private boolean downloadFile(UserToken myToken){
    // TODO: Decrypt file with GroupKey
    System.out.print("What file do you want to download? >> ");
    String sourceFile = console.next();
    System.out.print("What do you want to save it as? >> ");
    String destFile = console.next();
    boolean status = fileClient.download(sourceFile, destFile, myToken);
    if(status)
      System.out.println("Successfully downloaded file '" + sourceFile + "'\n");
    else
      System.out.println("Failed to download '" + sourceFile + "'\n");
    return status;
  }

  /**
   * Creates a group of the name specified where the owner is the token's subject
   * @param  group   Group to be created
   * @param  myToken Token of the user creating the group
   * @return         Success of operation
   */
  private boolean createGroup(UserToken myToken) {
    System.out.print("Name of the group you wish to create? >> ");
    String group = console.next();
    if(group.contains(":")){
      System.out.println("Group name cannot contain colons. ");
      return false;
    }
    boolean status = groupClient.createGroup(group, myToken);
    if (status) {
      System.out.println("Successfully created group '" + group + "'\n");
    } else {
        System.out.println("Failed to create group '" + group + "'\n");
    }
    return status;
  }

  /**
   * Deletes file specified if the token's subject belongs to the group
   * where the file belongs
   * @param  myToken Token of the user attempting to delete the file
   * @return         Success of operation
   */
  private boolean deleteFile(UserToken myToken) {
    System.out.print("Name of the file you wish to delete? >> ");
    String file = console.next();
    boolean status = fileClient.delete(file, myToken);
    if (status) {
      System.out.println("Successfully deleted file '" + file + "'\n");
    } else {
        System.out.println("Failed to delete file '" + file + "'\n");
    }
    return status;
  }


  // DEPRECATED -- no longer necessary since reconnect issue fixed
  /**
   * Resets the connection to the specified client with the given port
   * @param  Client client        Client object whose connection is to be reset
   * @param  int    port          Port to reconnect to (quietly)
   * @return        True on success
   */
  private boolean updateConnection(Client client, int port) {
    client.disconnect();
    return client.connect("127.0.0.1", port, true);
  }

  // DEPRECATED -- no longer necessary since reconnect issue fixed
  /**
   * Resets the connection to the specified client with the given host and port
   * @param  client   Client object whose connection is to be reset
   * @param  hostName Host to reconnect to
   * @param  port     Port to reconnect to
   * @return          True on success
   */
  private boolean updateConnection(Client client, String hostName, int port) {
    client.disconnect();
    return client.connect(hostName, port, true);
  }
}
