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
	private GCMParameterSpec spec;
	private byte [] iv, encRemotePath, encToken, buf;
	private int n;

	/**
	 * MUST MUST MUST be run before any other method
	 */
	public boolean keyExchange(PublicKey fileServerPublicKey) {
		Security.addProvider(new BouncyCastleProvider());
		Envelope env = new Envelope("KEYX");

		// Generate User's Keypair using Elliptic Curve D-H
		KeyPair clientKeyPair = ECDH.generateKeyPair();
		byte [] iv = SymmetricKeyOps.getGCM().getIV();

		env.addObject(clientKeyPair.getPublic());
		env.addObject(iv);
		try {
			output.writeObject(env);
			env = (Envelope)input.readObject();

			// Get Server's D-H public key signed by its RSA private key and get plaintext D-H public key
			byte [] serverSignedPubKey = (byte []) env.getObjContents().get(0);
			PublicKey serverPubKey = (PublicKey) env.getObjContents().get(1);

			// Hash plainKey to update signature object to verify File Server
			byte[] digest = SymmetricKeyOps.hash(serverPubKey.getEncoded());

			// Verify match using Server's RSA public key (from Trent)
			Signature pubSig = Signature.getInstance("SHA256withRSA", "BC");
			pubSig.initVerify(fileServerPublicKey);
			pubSig.update(digest);
			boolean match = pubSig.verify(serverSignedPubKey);

			// Generate Symmetric key from Server Public Key and Client Private Key
			if(match){ // Success
				this.sessionKey = ECDH.calculateKey(serverPubKey, clientKeyPair.getPrivate());
				return true;
			} else {
				System.out.println("Failed to establish key with File Server, unable to verify signature.");
				return false;
			}

		} catch (Exception e1) {
			e1.printStackTrace();
		}
		return false;
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/')
			remotePath = filename.substring(1);
		else
			remotePath = filename;

		Envelope env = new Envelope("DELETEF"); //Success
		spec = SymmetricKeyOps.getGCM();
		env.addObject(SymmetricKeyOps.encrypt(remotePath.getBytes(), this.sessionKey, spec));
		env.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(token), this.sessionKey, spec));
		env.addObject(spec.getIV());
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

							spec = SymmetricKeyOps.getGCM();
							env.addObject(SymmetricKeyOps.encrypt(sourceFile.getBytes(), this.sessionKey, spec));
							env.addObject(SymmetricKeyOps.encrypt(SymmetricKeyOps.obj2byte(token), this.sessionKey, spec));
							env.addObject(spec.getIV());

							output.writeObject(env);

					    env = (Envelope)input.readObject();

						while (env.getMessage().compareTo("CHUNK")==0) {
								iv = (byte[]) env.getObjContents().get(2);
								buf = SymmetricKeyOps.decrypt((byte[])env.getObjContents().get(0), sessionKey, iv);
								n = Integer.parseInt(new String(SymmetricKeyOps.decrypt((byte[])env.getObjContents().get(1), sessionKey, iv)));

								fos.write(buf, 0, n);
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
