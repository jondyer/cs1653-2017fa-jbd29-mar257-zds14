/**
 * This class does all the things.
 * Basic CLI for performing file and group operations.
 */
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

// Driver Class
public class RunClientApp {
  public static void main(String [] args) {
    ClientApp newApp = new ClientApp();
  }
}

class ClientApp {

  Scanner console = new Scanner(System.in);
  GroupClient client = new GroupClient();

  public ClientApp(){
    run();
  }
  public void run(){

    // Connect to Server
    client.connect("localhost", 8765);

    // Get Username & Token
    System.out.print("Welcome! Please login with your username >> ");
    String username = console.next();
    UserToken token = client.getToken(username);

    // Check to make sure token exists
    if(token == null) {
      System.out.println("Yo account ain't valid yo, we gettin outta here ");
      System.exit(0);
    }

    // Check if user has admin privileges
    boolean isAdmin = false;
    if(client.isAdmin(username)) {
      System.out.print("Are you performing administrative operations? (y/n) >> ");
      String response = console.next();

      // Wanna be a BIG boy?
      if(response.equals("y") || response.equals("Y"))
      isAdmin = true;
    }

    // Get groups belonged to
    List<List<String>> groupLists = client.listGroups(username, token);
    ArrayList<String> groupsBelongedTo = (ArrayList<String>) groupLists.get(0);
    ArrayList<String> groupsOwned = (ArrayList<String>) groupLists.get(1);

    // List groups
    System.out.println("These are the groups you belong to: ");
    for(int i=0; i<groupsBelongedTo.size(); i++)
    System.out.println(i + ") " + groupsBelongedTo.get(i));

    // Select a group
    System.out.print("Please select a group you wish to access >> ");
    String choice = groupsBelongedTo.get(Integer.parseInt(console.next()));
    boolean isOwner = false;

    // Check if owner of selected group
    if(groupsOwned.contains(choice) && !isAdmin) {
      System.out.println("Would you to perform owner actions? (y/n) >> ");
      String response = console.next();

      // Wanna be a big boy?
      if(response.equals("y") || response.equals("Y"))
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
    while(doAgain) {
      // Menu, show selected group and access level
      System.out.println("----MENU----");
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

      System.out.print("Please select an option (q = quit) >> ");
      String response = console.next();
      switch(response){

        // ADMIN ACTIONS -----------------
        case "a0":
        // Create user
        if(isAdmin)
        createUser(token);
        break;
        case "a1":
        // Delete user
        if(isAdmin)
        deleteUser(token);
        break;

        // OWNER ACTIONS -----------------
        case "o0":
        // List members of a group

        break;
        case "o1":
        // Add user to a group

        break;
        case "o2":
        // Remove user from a group

        break;
        case "o3":
        // Delete group

        break;

        // USER ACTIONS -----------------
        case "0":
        // List files
        break;
        case "1":
        // Upload files

        break;
        case "2":
        // Download files

        break;
        case "3":
        // Delete files

        break;
        case "4":
        // Create a group

        break;
        case "q":
        //quit
        doAgain = false;
        break;
        default:
        // Invalid choice
        System.out.println("Not a valid menu choice");
        break;
      }
    }
    client.disconnect();


  } //end main

  /**
  * Creates a user in the system (ADMIN ONLY)
  * @param  UserToken myToken       Token of the administrator
  * @return           Status of operation
  */
  public boolean createUser(UserToken myToken) {
    System.out.print("Username of the person you wish to create? >> ");
    String username = console.next();
    boolean status = client.createUser(username, myToken);
    if(status)
    System.out.println("Successfully created user '" + username + "'\n");
    else
    System.out.println("Failed to create user '" + username + "'\n");
    return status;
  }

  /**
  * Deletes a user from the system (ADMIN ONLY)
  * @param  UserToken myToken       Token of the administrator
  * @return           Status of operation
  */
  public boolean deleteUser(UserToken myToken) {
    System.out.print("Username of the person you wish to delete? >> ");
    String username = console.next();
    boolean status = client.deleteUser(username, myToken);
    if(status)
    System.out.println("Successfully deleted user '" + username + "'\n");
    else
    System.out.println("Failed to delete user '" + username + "'\n");
    return status;
  }
}
