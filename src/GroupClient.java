/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.io.IOException;
import javax.crypto.*;
import java.security.*;

import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;

public class GroupClient extends Client implements GroupClientInterface {

	// We selected group 21 a.k.a. group p-521 (elliptic curve) for our system
	private static final BigInteger g_1024 = new BigInteger(1, Hex.decode("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
        + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
        + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
        + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
        + "FD5138FE8376435B9FC61D2FC0EB06E3"));
  private static final BigInteger N_1024 = new BigInteger(1, Hex.decode("000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
	private final SecureRandom random = new SecureRandom();
	private SecretKey K;

	// TODO: Get SRP to work
	public boolean clientSRP() {
		Security.addProvider(new BouncyCastleProvider());
		BigInteger A = null;
		BigInteger S = null;

		byte[] I = "username".getBytes();
        byte[] P = "password".getBytes();
        byte[] s = new byte[32];
        random.nextBytes(s);

        SRP6Client client = new SRP6Client();
        client.init(N_1024, g_1024, new SHA256Digest(), random);
        A = client.generateClientCredentials(s, I, P);

        Envelope response = null;
        Envelope message = new Envelope("SRP");
        message.addObject("username");
        message.addObject(A);

        try {
	        output.writeObject(message);
	        response = (Envelope)input.readObject();
        } catch (IOException io) {
        	System.out.println(io.getMessage());
        } catch (ClassNotFoundException cl) {
        	System.out.println(cl.getMessage());
        }

        try {
        	S = client.calculateSecret((BigInteger)response.getObjContents().get(0));
        } catch (CryptoException cry) {
        	System.out.println(cry.getMessage());
        }

        K = new SecretKeySpec(S.toByteArray(), 0, 16, "AES");

        byte[] cypherText = (byte[]) response.getObjContents().get(2);
        byte[] plain = SymmetricKeyOps.decrypt(cypherText, K, (byte[]) response.getObjContents().get(1));

		System.out.println(new String(plain));

        return true;
	}

	public UserToken getToken(String username) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("OK")) {
				//If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 1) {
					token = (UserToken)temp.get(0);
					return token;
				}
			}

			return null;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	 }

		/**
		* Overloaded method for retrieving partial tokens (for group-specific operations
		* @param  String username      Owner of the token
		* @param  String groupname     The group they want to operate in
		* @return        The newly constructed partial token
		*/
		public UserToken getToken(String username, String groupname) {
			try {
				UserToken token = null;
				Envelope message = null, response = null;

				//Tell the server to return a token.
				message = new Envelope("GET");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add groupname
				output.writeObject(message);

				//Get the response from the server
				response = (Envelope)input.readObject();

				//Successful response
				if(response.getMessage().equals("OK")) {
					//If there is a token in the Envelope, return it
					ArrayList<Object> temp = null;
					temp = response.getObjContents();

					if(temp.size() == 1) {
						token = (UserToken)temp.get(0);
						return token;
					}
				}
				return null;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

  public boolean isAdmin(String username) {
    return (getToken(username, "ADMIN") != null);
  }


	// Deprecated I think?
	public boolean createUser(String username, UserToken token) {
		 try {
				Envelope message = null, response = null;
				//Tell the server to create a user
				//If no password is given, initialize to empty
				String pw = "";
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(pw); //Add user password
				message.addObject(token); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	}

	 // Overload for password
	 public boolean createUser(String username, String pw, UserToken token) {
		 try {
				Envelope message = null, response = null;
				//Tell the server to create a user
				//If no password is given, initialize to empty
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(pw); //Add user password
				message.addObject(token); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, UserToken token) {
		 try {
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean createGroup(String groupname, UserToken token) {
		 try {
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, UserToken token){
		 try {
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token) {
		 try {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.

			 return null;

		 } catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<List<String>> listGroups(String user, UserToken token) {
		 try {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LGROUPS");
			 message.addObject(user); //Add username string
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				return (List<List<String>>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 } catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listAllGroups(UserToken token) {
		 try {
			 Envelope message = null, response = null;
			 //Tell the server to return the group list
			 message = new Envelope("LAGROUPS");
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the group list
			 if(response.getMessage().equals("OK"))
			 {
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 } catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listAllUsers(UserToken token) {
		 try {
			 Envelope message = null, response = null;
			 //Tell the server to return the group list
			 message = new Envelope("LAUSERS");
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the user list
			 if(response.getMessage().equals("OK"))
			 {
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 } catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }


	 public boolean addUserToGroup(String username, String groupname, UserToken token) {
		 try {
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
		 try {
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
					return true;

				return false;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

}
