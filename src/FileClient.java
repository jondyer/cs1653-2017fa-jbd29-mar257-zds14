/* FileClient provides all the client functionality regarding the file server */

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

import java.lang.Thread;
import java.net.Socket;

import java.security.*;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;


public class FileClient extends Client implements FileClientInterface {

	private SecretKey sessionKey;

	/**
	 * Default constructor for FileClient class. Runs super's constructor then establishes key with file (thread) server.
	 * @return [description]
	 */
	public FileClient(){
		// TODO: Fix constructor and stuff???
		super();
		try{
			keyExchange();
		} catch(Exception e){
			e.printStackTrace();
		}
	}

	/**
	 * MUST MUST MUST be run before any other method
	 */
	public void keyExchange() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		Security.addProvider(new BouncyCastleProvider());
		Envelope env = new Envelope("KEYX");


		SecureRandom rand = new SecureRandom();
		byte[] iv = new byte[16];
		rand.nextBytes(iv);

		// Generate User's Keypair using Elliptic Curve D-H
		KeyPair clientKeyPair = ECDH.generateKeyPair();

		env.addObject(clientKeyPair.getPublic());
		env.addObject(iv);
		try {
			output.writeObject(env);

			// Get Server's public key and ciphertext
			env = (Envelope)input.readObject();
			PublicKey serverPubKey = (PublicKey) env.getObjContents().get(0);
			byte [] cipherText = (byte []) env.getObjContents().get(1);
			System.out.println(new String(cipherText));

			// Generate Symmetric key from Server Private Key and Client Public Key
			SecretKey sessionKey = ECDH.calculateKey(serverPubKey, clientKeyPair.getPrivate());

			// Decrypt
			Cipher deCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			deCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
			byte[] plainText = deCipher.doFinal(cipherText);
			System.out.println(new String(plainText));


		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/')
			remotePath = filename.substring(1);
		else
			remotePath = filename;

		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {
				output.writeObject(env);
				env = (Envelope)input.readObject();

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}

				File file = new File(destFile);
			    try {


				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);

					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env);

					    env = (Envelope)input.readObject();

						while (env.getMessage().compareTo("CHUNK")==0) {
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env);
								env = (Envelope)input.readObject();
						}
						fos.close();

						if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(env);
						} else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;
							}
				    }

				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }


					} catch (IOException e1) {

			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;


				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 e = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.


			 return (new ArrayList<String>());

			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return (new ArrayList<String>());
			}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token) {

		if (destFile.charAt(0)!='/')
			destFile = "/" + destFile;


		try {

			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);


			 FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
				System.out.printf("Meta data upload successful\n");
			 else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }


			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					message.addObject(buf);
					message.addObject(new Integer(n));

					output.writeObject(message);


					env = (Envelope)input.readObject();


			 } while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0) {

				message = new Envelope("EOF");
				output.writeObject(message);

				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0)
					System.out.printf("\nFile data upload successful\n");
				else {
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }

				} else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			  }

		 } catch(Exception e1) {
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
		 }
		return true;
	}
}
