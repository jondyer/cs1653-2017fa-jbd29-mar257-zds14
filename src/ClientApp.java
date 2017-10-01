/**
 * This class does all the things.
 * Basic CLI for performing file and group operations.
 */
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

public class ClientApp {
    public static void main(String [] args){

      //Connect to Server
      GroupClient client = new GroupClient();
      client.connect("localhost", 8765);

      //Get Username & Token
      Scanner console = new Scanner(System.in);
      System.out.print("Welcome! Please login with your username >> ");
      String username = console.next();
      UserToken token = client.getToken(username);

      //Check to make sure token exists
      if(token == null) {
        System.out.println("Yo account ain't valid yo, we gettin outta here ");
        System.exit(0);
      }

      //Check if user has admin privileges
      //TODO: Fix Admin Privileges Section
      boolean isAdmin = false;
      if(client.isAdmin(username)) {
        System.out.print("Are you performing administrative operations? (y/n) >> ");
        String response = console.next();

        //Wanna be a big boy?
        if(response.equals("y") || response.equals("Y")) {
          isAdmin = true;
          // token = client.getToken(username, "ADMIN");
          // Do Stuff
        }
      }

      //Get groups belonged to
      List<List<String>> groupLists = client.listGroups(username, token);
      ArrayList<String> groupsBelongedTo = (ArrayList<String>) groupLists.get(0);
      ArrayList<String> groupsOwned = (ArrayList<String>) groupLists.get(1);

      //List groups
      System.out.println("These are the groups you belong to: ");
      for(int i=0; i<groupsBelongedTo.size(); i++)
        System.out.println(i + ") " + groupsBelongedTo.get(i));

      //Select a group
      System.out.print("Please select a group you wish to access >> ");
      String choice = groupsBelongedTo.get(Integer.parseInt(console.next()));
      boolean isOwner = false;

      //Check if owner of selected group
      if(groupsOwned.contains(choice)){
        System.out.println("Would you to perform owner actions? (y/n) >> ");
        String response = console.next();

        //Wanna be a big boy?
        if(response.equals("y") || response.equals("Y"))
          isOwner = true;
      }


      //Menu
      System.out.println("----MENU----");
      System.out.println("Selected Group: " + choice);
      if(isAdmin)
        System.out.println("Operating as Admin");
      else if(isOwner)
        System.out.println("Operating as Owner");
      else
        System.out.println("Operating as User");




      client.disconnect();
    }
}
