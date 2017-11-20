/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.List;
import java.util.*;
import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;

public class GroupThread extends Thread {
  private final Socket socket;
  private GroupServer my_gs;
  private SecretKey K;
  private GCMParameterSpec spec;
  private byte[] iv;

  private static final BigInteger g_1024 = new BigInteger(1, Hex.decode("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
        + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
        + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
        + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
        + "FD5138FE8376435B9FC61D2FC0EB06E3"));
  private static final BigInteger N_1024 = new BigInteger(1, Hex.decode("000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));

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
      byte[] c1 = new byte[12]; // Challenge to be looked at in CHAL

      do {
        Envelope message = (Envelope)input.readObject();
        System.out.println("Request received: " + message.getMessage());
        Envelope response = new Envelope("FAIL");

        if (message.getMessage().equals("SRP")) {
          if(message.getObjContents().size() < 2)
            response = new Envelope("FAIL");
          else {
            response = new Envelope("FAIL");

            if(message.getObjContents().get(0) != null) {
              if(message.getObjContents().get(1) != null) {
                String username = (String)message.getObjContents().get(0); //Extract the username
                BigInteger A = (BigInteger)message.getObjContents().get(1); //Extract the public key from the client
                BigInteger B = genSessionKey(username, A);
                SecureRandom random = new SecureRandom();

                random.nextBytes(c1); // 96 bit challenge

                if (B != null) {
                  response = new Envelope("OK");
                  response.addObject(B);
                  response.addObject(c1);
                  output.writeObject(response);
                }
              }
            }
          }
        } else if(message.getMessage().equals("SALT")) {
          if(message.getObjContents().size() < 1)
            response = new Envelope("FAIL");
          else {
            response = new Envelope("FAIL");

            if(message.getObjContents().get(0) != null) {
              String username = (String)message.getObjContents().get(0); //Extract the username

              response.addObject(my_gs.userList.getSalt(username));
            }
          }
          output.writeObject(response);
        } else if(message.getMessage().equals("CHAL")) {
          if(message.getObjContents().size() < 3)
            response = new Envelope("FAIL");
          else {
            response = new Envelope("FAIL");

            if(message.getObjContents().get(0) != null) {
              byte[] iv = (byte[])message.getObjContents().get(0);
              byte[] c1Cipher = (byte[])message.getObjContents().get(1);
              byte[] c2 = (byte[])message.getObjContents().get(2);

              byte[] c1_dec = SymmetricKeyOps.decrypt(c1Cipher, K, iv);
              if(!Arrays.equals(c1, c1_dec)) {
                output.writeObject(response);
                System.out.println("Error: Challenge did not match!");
                //System.exit(0);
              }

              GCMParameterSpec gcm = SymmetricKeyOps.getGCM();
              response = new Envelope("OK");
              response.addObject(gcm.getIV());
              response.addObject(SymmetricKeyOps.encrypt(c2, K, gcm));
              output.writeObject(response);
            }
          }
        } else if(message.getMessage().equals("GET")) { //Client wants a token
          iv = (byte[])message.getObjContents().get(0);   // Get the IV
          spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec
          byte[] namebytes = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec); //Decrypt the username
          String username;
          username = new String(namebytes); //Convert to String

          if(username == null) {
            response = new Envelope("FAIL");
            response.addObject(null);
            output.writeObject(response);
          } else if(message.getObjContents().size() > 2) {  // this is for partial tokens
            String groupname;
            namebytes = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec); //Decrypt the groupname
            groupname = new String(namebytes); //Convert to String
            UserToken yourToken = createToken(username, groupname); //Create a token with the specified group

            if(yourToken != null) {
              //Respond to the client. On error, the client will receive a null token
              response = new Envelope("OK");
              spec = SymmetricKeyOps.getGCM();
              response.addObject(spec.getIV());
              response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(yourToken), K, spec));
              response.addObject(my_gs.signAndHash(((Token)yourToken).getIdentifier()));
            }

            output.writeObject(response);
          } else {
            UserToken yourToken = createToken(username); //Create a token

            //Respond to the client. On error, the client will receive a null token
            response = new Envelope("OK");
            spec = SymmetricKeyOps.getGCM();
            response.addObject(spec.getIV());
            response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(yourToken), K, spec));
            response.addObject(my_gs.signAndHash(((Token)yourToken).getIdentifier()));
            output.writeObject(response);
          }
        } else if(message.getMessage().equals("CUSER")){ //Client wants to create a user
          if(message.getObjContents().size() < 4)
            response = new Envelope("FAIL");
          else {
            response = new Envelope("FAIL");

            if(message.getObjContents().get(0) != null) {
              if(message.getObjContents().get(1) != null) {
                iv = (byte[])message.getObjContents().get(0);   // Get the IV
                spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                String username = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the username

                byte[] salt = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec); // Extract the salt
                BigInteger password = new BigInteger(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec)); //Extract the password
                UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(4), K, spec)); //Extract the token
                byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(5), K, spec);
                if(!verifyToken((Token) yourToken, signedHash))
                  response = new Envelope("FAIL");
                else if(createUser(username, salt, password, yourToken)){
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
                iv = (byte[])message.getObjContents().get(0);   // Get the IV
                spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                String username = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the username
                UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); //Extract the token
                byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec);
                if(!verifyToken((Token) yourToken, signedHash))
                  response = new Envelope("FAIL");
                else if(deleteUser(username, yourToken))
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
                iv = (byte[])message.getObjContents().get(0);   // Get the IV
                spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                String groupName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the username
                UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); //Extract the token
                byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec);
                if(!verifyToken((Token) yourToken, signedHash))
                  response = new Envelope("FAIL");
                else if(createGroup(groupName, yourToken))
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
                  iv = (byte[])message.getObjContents().get(0);   // Get the IV
                  spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                  String groupName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the username
                  UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); //Extract the token
                  byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec);
                  if(!verifyToken((Token) yourToken, signedHash))
                    response = new Envelope("FAIL");
                  else if(deleteGroup(groupName, yourToken)) {
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
                  iv = (byte[])message.getObjContents().get(0);   // Get the IV
                  spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                  String groupName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the username
                  UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); //Extract the token
                  byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec);
                  List<String> members = listMembers(groupName, yourToken);
                  if(!verifyToken((Token) yourToken, signedHash))
                    response = new Envelope("FAIL");
                  else if(members.size() > 0) {
                    response = new Envelope("OK"); //Success

                    spec = SymmetricKeyOps.getGCM();
                    response.addObject(spec.getIV());
                	  response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(members), K, spec));  // add encrypted list
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
                  iv = (byte[])message.getObjContents().get(0);   // Get the IV
                  spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                  String userName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the username
                  UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); //Extract the token
                  byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec);
                  if(!verifyToken((Token) yourToken, signedHash))
                    response = new Envelope("FAIL");
                  else {
                    List<List<String>> resp = listGroups(userName, yourToken);


                    response = new Envelope("OK"); //Success
                    spec = SymmetricKeyOps.getGCM();
                    response.addObject(spec.getIV());
                    response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(resp), K, spec));  // add encrypted token array
                  }
                }
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("LAGROUPS")) { //Client wants a list of all groups
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 1) {
              if(message.getObjContents().get(0) != null) {
                iv = (byte[])message.getObjContents().get(0);   // Get the IV
                spec = SymmetricKeyOps.getGCM(iv);    // Get GCM Spec

                UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); //Extract the token
                byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec);
                if(!verifyToken((Token) yourToken, signedHash))
                  response = new Envelope("FAIL");
                else {
                  List<String> groups = listAllGroups(yourToken);
                  if (groups != null) {
                    response = new Envelope("OK"); //Success

                    spec = SymmetricKeyOps.getGCM();
                    response.addObject(spec.getIV());
                    response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(groups), K, spec));  // add encrypted token array
                  }
                }
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("LAUSERS")) { //Client wants a list of all users
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 1) {
              if(message.getObjContents().get(0) != null) {
                spec = SymmetricKeyOps.getGCM((byte[]) message.getObjContents().get(0));
                UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); // Extract the token
                byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec);
                if(!verifyToken((Token) yourToken, signedHash))
                  response = new Envelope("FAIL");
                else {
                  List<String> users = listAllUsers(yourToken);
                  spec = SymmetricKeyOps.getGCM();
                  byte[] encUsers = SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(users), K, spec);
                  if (users != null)
                  response = new Envelope("OK"); //Succes
                  response.addObject(spec.getIV());
                  response.addObject(encUsers);
                }
              }
            }

          output.writeObject(response);
        } else if(message.getMessage().equals("AUSERTOGROUP")) {//Client wants to add user to a group
          response = new Envelope("FAIL");

          if(message.getObjContents().size() >= 4) {
            if(message.getObjContents().get(0) != null) {
              if(message.getObjContents().get(1) != null) {
                if(message.getObjContents().get(2) != null) {
                  if(message.getObjContents().get(3) != null) {
                    spec = SymmetricKeyOps.getGCM((byte[]) message.getObjContents().get(0));
                    String userName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); // Extract the username
                    String groupName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); // Extract the groupName
                    UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec)); // Extract the token
                    byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(4), K, spec);
                    if(!verifyToken((Token) yourToken, signedHash))
                      response = new Envelope("FAIL");
                    else if(addUserToGroup(userName, groupName, yourToken))
                    response = new Envelope("OK"); //Success
                  } // missing token
                } // missing groupName
              } // missing userName
            } // missing iv
          } // missing something!
          output.writeObject(response);
        } else if(message.getMessage().equals("RUSERFROMGROUP")) {//Client wants to remove user from a group
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 4) {
              if(message.getObjContents().get(0) != null) {
                if(message.getObjContents().get(1) != null) {
                  if(message.getObjContents().get(2) != null) {
                    if(message.getObjContents().get(3) != null) {
                      spec = SymmetricKeyOps.getGCM((byte[]) message.getObjContents().get(0));
                      String userName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); // Extract the username
                      String groupName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); // Extract the groupName
                      UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec)); // Extract the token
                      byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(4), K, spec);
                      if(!verifyToken((Token) yourToken, signedHash))
                        response = new Envelope("FAIL");
                      else if(deleteUserFromGroup(userName, groupName, yourToken))
                      response = new Envelope("OK"); //Success
                    } // missing token
                  } // missing groupName
                } // missing userName
              } // missing iv
            } // missing something!
            output.writeObject(response);
        } else if(message.getMessage().equals("GROUPKEY")) {//Client wants to remove user from a group
            response = new Envelope("FAIL");

            if(message.getObjContents().size() >= 4) {
              if(message.getObjContents().get(0) != null) {
                if(message.getObjContents().get(1) != null) {
                  if(message.getObjContents().get(2) != null) {
                    if(message.getObjContents().get(3) != null) {
                      spec = SymmetricKeyOps.getGCM((byte[]) message.getObjContents().get(0));
                      String userName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(1), K, spec)); // Extract the username
                      String groupName = new String(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(2), K, spec)); // Extract the groupName
                      UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(3), K, spec)); // Extract the token
                      byte [] signedHash = SymmetricKeyOps.decrypt((byte[])message.getObjContents().get(4), K, spec);
                      if(verifyToken((Token) yourToken, signedHash)) {
                        // verify it is the users token and the user is in the group
                        if (userName.equals(yourToken.getSubject()) && my_gs.groupList.getGroupUsers(groupName).contains(userName)){
                          response = new Envelope("OK");
                          // add key and hashNum
                          spec = SymmetricKeyOps.getGCM();
                          response.addObject(spec.getIV());
                          response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(my_gs.groupList.getKey(groupName)), K, spec));
                          response.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(my_gs.groupList.getHashNum(groupName)), K, spec));
                        }
                      }
                      response = new Envelope("FAIL"); //Success
                    } // missing token
                  } // missing groupName
                } // missing userName
              } // missing iv
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
    catch(EOFException ex){

    }
    catch(SocketException ex){

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

  private BigInteger genSessionKey(String user, BigInteger A) {
    Security.addProvider(new BouncyCastleProvider());

    BigInteger B = null;
    BigInteger S = null;

    SRP6Server server = new SRP6Server();

    server.init(N_1024, g_1024, my_gs.userList.getPass(user), new SHA256Digest(), new SecureRandom());
    B = server.generateServerCredentials();

    try {
      S = server.calculateSecret(A);
    } catch (CryptoException cry) {
      System.out.println(cry.getMessage());
    }

    K = new SecretKeySpec(S.toByteArray(), 0, 16, "AES");

    return B;
  }

  //Method to create a user
  private boolean createUser(String username, byte[] salt, BigInteger password, UserToken yourToken) {
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
          my_gs.userList.addUser(username, salt, password);
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

/**
 * Verifies a token from the User to make sure it originated from the GroupServer
 * @param  Token  tokenToVerify         Token from User
 * @param  String groupServerSignedHash GroupServer-Signed Hash that accompanies token
 * @return        Status of if the signed hash matched the token
 */
  private boolean verifyToken(Token tokenToVerify, byte[] groupServerSignedHash) {
    try {
      // Hash identifier of recovered token
      String identifier = tokenToVerify.getIdentifier();
      byte [] hashedIdentifier = SymmetricKeyOps.hash(identifier);

      // Verify contents of GroupServer-Signed hash using recovered hash and Group Server's Public Key
      Signature pubSig = Signature.getInstance("SHA256withRSA", "BC");
      pubSig.initVerify(this.my_gs.pub);
      pubSig.update(hashedIdentifier);
      boolean match = pubSig.verify(groupServerSignedHash);
      System.out.println("Verifying User's Token.... " + match);
      if(match) return true;

    } catch (Exception e){}
      return false;
  }
}
