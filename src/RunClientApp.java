/**
 * This class does all the things.
 * Basic CLI for performing file and group operations.
 */
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import java.io.File;

// Driver Class
public class RunClientApp {
  public static void main(String [] args) {
    ClientApp newApp = new ClientApp();
  }
}

class ClientApp {

  Scanner console = new Scanner(System.in);
  GroupClient groupClient = new GroupClient();
  FileClient fileClient = new FileClient();

  public ClientApp(){
    run();
  }
  public void run(){

    // Connect to Server
    final int GROUP_PORT = 8765;
    final int FILE_PORT = 4321;
    groupClient.connect("localhost", GROUP_PORT);
    fileClient.connect("localhost", FILE_PORT);

    // Get Username & Token
    System.out.print("Welcome! Please login with your username >> ");
    String username = console.next();
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

      // Select a group
      System.out.print("Please select a group you wish to access ('q' to quit, 'c' to create a new group) >> ");
      String selection = console.next();
      if(selection.equals("q")) {
        selectGroup = false;
        break;
      }
      //TODO: Make group actually appear after creating it
      if(selection.equals("c")) {
        createGroup(token);
        updateConnection(groupClient, GROUP_PORT);
        continue;
      }
      String choice = groupsBelongedTo.get(Integer.parseInt(selection));
      boolean isOwner = false;

      // Check if owner of selected group
      if(groupsOwned.contains(choice) && !isAdmin) {
        System.out.println("Would you to perform owner actions? (y/n) >> ");
        String response = console.next();

        // Wanna be a big boy?
        if(response.equals("y") || response.equals("Y"))
        isOwner = true;
      } else if (groupsOwned.contains(choice) && isAdmin) {
        isOwner = true;
      }


      // Compile List of privileges for each level of usage
      ArrayList<String> adminList = new ArrayList<String>();
      adminList.add("Create user");
      adminList.add("Delete user");
      ArrayList<String> ownerList = new ArrayList<String>();
      ownerList.add("List members of a group");
      ownerList.add("Add user to group");
      ownerList.add("Remove user from group");
      ownerList.add("Delete group");
      ArrayList<String> userList = new ArrayList<String>();
      userList.add("List files");
      userList.add("Upload files");
      userList.add("Download files");
      userList.add("Delete files");
      userList.add("Create a group");

      boolean doAgain = true;
      groupChoice: while(doAgain) {   // labeled while for convenience later on
        // Menu, show selected group and access level
        System.out.println("\n\n----MENU----");
        System.out.println("Selected Group: " + choice);
        if(isAdmin){
          System.out.println("Operating as Admin");
        } else if(isOwner){
          System.out.println("Operating as Owner");
        } else {
          System.out.println("Operating as User");
        }
        System.out.println("\n");

        // List options for each privilege level
        if(isAdmin){
          System.out.println("Admin Ops:");
          for(int i = 0; i < adminList.size(); i++)
          System.out.println("a" + i + ") " + adminList.get(i));
          System.out.println("\n");
        }
        if(isOwner){
          System.out.println("Owner Ops:");
          for(int i = 0; i < ownerList.size(); i++)
          System.out.println("o" + i + ") " + ownerList.get(i));
          System.out.println("\n");
        }
        System.out.println("User Ops:");
        for(int i = 0; i < userList.size(); i++)
        System.out.println(i + ") " + userList.get(i));
        System.out.println("\n");

        System.out.print("Please select an option ('q' to select a different group) >> ");
        String response = console.next();
        switch(response) {
          // ADMIN ACTIONS -----------------

          // Create user
          case "a0":
            if(isAdmin) createUser(token);
            updateConnection(groupClient, GROUP_PORT);
            break;

          // Delete user
          case "a1":
            if(isAdmin) deleteUser(token);
            updateConnection(groupClient, GROUP_PORT);
            break;

          // OWNER ACTIONS -----------------
          // List members of a group
          case "o0":
            if(isOwner) listMembers(choice, token);
            break;

          // Add user to a group
          case "o1":
            if(isOwner) addUserToGroup(choice, token);
            updateConnection(groupClient, GROUP_PORT);
            break;

          // Remove user from a group
          case "o2":
            if(isOwner) removeUserFromGroup(choice, token);
            updateConnection(groupClient, GROUP_PORT);
            break;

          // Delete group
          case "o3":
            if(isOwner) deleteGroup(choice, token);
            updateConnection(groupClient, GROUP_PORT);
            break groupChoice;

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
            updateConnection(groupClient, GROUP_PORT);
            break;

          //quit
          case "q":
            doAgain = false;
            break;

          // Invalid choice
          default:
            System.out.println("Not a valid menu choice");
            break;
        }
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
  public boolean createUser(UserToken myToken) {
    System.out.print("Username of the person you wish to create? >> ");
    String username = console.next();
    boolean status = groupClient.createUser(username, myToken);
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
  public boolean deleteUser(UserToken myToken) {
    System.out.print("Username of the person you wish to delete? >> ");
    String username = console.next();
    boolean status = groupClient.deleteUser(username, myToken);
    if(status)
      System.out.println("Successfully deleted user '" + username + "'\n");
    else
      System.out.println("Failed to delete user '" + username + "'\n");
    return status;
  }

  /**
   * Lists all members of a group.
   * @param  String    group         Name of the group to list members for
   * @param  UserToken myToken       Token of the owner of the group
   */
  public void listMembers(String group, UserToken myToken) {
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
  public boolean addUserToGroup(String group, UserToken myToken) {
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
  public boolean removeUserFromGroup(String group, UserToken myToken) {
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
  public boolean deleteGroup(String group, UserToken myToken) {
    System.out.print("Are you sure you wish to delete group '" + group + "' and remove all users from it? (y/n) >> ");
    String choice = console.next();
    if(choice.equals("Y") || choice.equals("y")) {
      boolean status = groupClient.deleteGroup(group, myToken);
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
  public void listFiles(UserToken myToken) {
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
  public boolean uploadFile(String group, UserToken myToken) {
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
  public boolean downloadFile(UserToken myToken){
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
  public boolean createGroup(UserToken myToken) {
    System.out.print("Name of the group you wish to create? >> ");
    String group = console.next();
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
  public boolean deleteFile(UserToken myToken) {
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

  /**
   * Resets the connection to the specified client with the given port
   * @param  Client client        Client object whose connection is to be reset
   * @param  int    port          Port to reconnect to (quietly)
   * @return        True on success
   */
  private boolean updateConnection(Client client, int port) {
    client.disconnect();
    return client.connect("localhost", port, true);
  }
}
