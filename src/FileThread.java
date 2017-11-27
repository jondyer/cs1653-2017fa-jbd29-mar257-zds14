/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

import java.lang.Thread;
import java.net.Socket;

import java.security.*;
import java.security.spec.*;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;



public class FileThread extends Thread {
	private final Socket socket;
	private FileServer my_fs;
	private SecretKey sessionKey;
	private GCMParameterSpec spec;
	private byte[] iv, encRemotePath, encToken, signedHash;
	private String remotePath;
	private Token t;
	private PublicKey groupServerPublicKey;
	ArrayList<Object> temp = null;



	public FileThread(Socket _socket, FileServer _fs) {
		this.socket = _socket;
		this.my_fs = _fs;
		Security.addProvider(new BouncyCastleProvider());
	}

	public void run() {
		boolean proceed = true;
		try {
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do {
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				//Handler to establish session key between Client and FileServer
				if(e.getMessage().equals("KEYX")) {
					if(e.getObjContents().size() < 1) response = new Envelope("FAIL-BADCONTENTS");
					else {
						// Get client's Public Key & Initialization vector
						PublicKey clientPubKey = (PublicKey) e.getObjContents().get(0);
						IvParameterSpec ivSpec = new IvParameterSpec((byte[]) e.getObjContents().get(1));

						// Generate Keypair for Server
						KeyPair serverKeyPair = ECDH.generateKeyPair();

						// Generate Symmetric key from Server Private Key and Client Public Key
						this.sessionKey = ECDH.calculateKey(clientPubKey, serverKeyPair.getPrivate());

						// Hash FS's D-H public key (to reduce size for signing)
						byte[] digest = SymmetricKeyOps.hash(serverKeyPair.getPublic().getEncoded());

						// Sign D-H public key hash using RSA private key
						Signature privSig = Signature.getInstance("SHA256withRSA", "BC");
						privSig.initSign(my_fs.priv);
						privSig.update(digest);
						byte [] signedDHPubKey = privSig.sign(); // Generate updated signature

						// Send Response
						response = new Envelope("OK");
						response.addObject(signedDHPubKey);	// Send Hashed D-H public key signed by RSA private key
						response.addObject(serverKeyPair.getPublic()); // Send plaintext D-H public key
						output.writeObject(response);


						// Receive GroupServer pubKey and verify
						Envelope env = (Envelope)input.readObject();
						this.groupServerPublicKey = (PublicKey) env.getObjContents().get(0);
					}
				}

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES")) {

					if (e.getObjContents().size() < 1)
						response = new Envelope("FAIL-BADCONTENTS");
					else {
							if (e.getObjContents().get(0) == null)
								response = new Envelope("FAIL-BADTOKEN");
							else {
								temp = e.getObjContents();
								iv = (byte[]) temp.get(1);
								Token yourToken = (Token) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt((byte[]) temp.get(0), this.sessionKey, iv));
								signedHash = SymmetricKeyOps.decrypt((byte[])temp.get(2), this.sessionKey, iv);
								if(!verifyToken(yourToken, signedHash))
									response = new Envelope("FAIL");
								else {
									List<ShareFile> fullFileList = FileServer.fileList.getFiles();
									List<String> userFileList = new ArrayList<String>();
									List<String> groups = yourToken.getGroups();

									if (fullFileList != null) {
										for (ShareFile sf: fullFileList) {
											if (groups.contains(sf.getGroup()))
											userFileList.add(sf.getPath() + "\t(" + sf.getGroup() + ":" + sf.getOwner() + ")");
										}
									}
									ByteArrayOutputStream bos = new ByteArrayOutputStream();
									ObjectOutput out = null;
									spec = SymmetricKeyOps.getGCM();
									byte[] yourBytes = SymmetricKeyOps.obj2byte(userFileList);
									byte[] encByteList = SymmetricKeyOps.encrypt(yourBytes, this.sessionKey, spec);

									response = new Envelope("OK"); // Success

									response.addObject(encByteList);
									response.addObject(spec.getIV());
								}
							}
					}
					output.writeObject(response);
				}
				if(e.getMessage().equals("UPLOADF")) {

					if(e.getObjContents().size() < 3)
						response = new Envelope("FAIL-BADCONTENTS");
					else {
						if(e.getObjContents().get(0) == null)
							response = new Envelope("FAIL-BADPATH");

						if(e.getObjContents().get(1) == null)
							response = new Envelope("FAIL-BADGROUP");

						if(e.getObjContents().get(2) == null)
							response = new Envelope("FAIL-BADTOKEN");
						else {
							temp = e.getObjContents();
							// Get contents from envelope
							encRemotePath = (byte[]) temp.get(0);
							byte[] encGroup = (byte[]) temp.get(1);
							encToken = (byte[]) temp.get(2);
							iv = (byte[]) temp.get(3);
							signedHash = SymmetricKeyOps.decrypt((byte[])temp.get(4), this.sessionKey, iv);
							UserToken yourToken = (UserToken) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt(encToken, this.sessionKey, iv));
							int hashNum = Integer.parseInt(new String(SymmetricKeyOps.decrypt((byte[])e.getObjContents().get(5), this.sessionKey, iv)));
							byte[] groupIV = (byte[]) temp.get(6);
							if(!verifyToken((Token) yourToken, signedHash))
								response = new Envelope("FAIL");
							else {
								// Decrypt contents
								String remotePath = new String(SymmetricKeyOps.decrypt(encRemotePath, this.sessionKey, iv));
								String group = new String(SymmetricKeyOps.decrypt(encGroup, this.sessionKey, iv));

								if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope("FAIL-FILEEXISTS"); //Success
								} else if (!yourToken.getGroups().contains(group)) {
									for (String i : yourToken.getGroups())
									System.out.println("Group = " + i);
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope("FAIL-UNAUTHORIZED"); //Success
								} else {
									File file = new File("shared_files/"+remotePath.replace('/', '_'));
									file.createNewFile();
									FileOutputStream fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

									response = new Envelope("READY"); //Success
									output.writeObject(response);

									e = (Envelope)input.readObject();

									iv = (byte[]) e.getObjContents().get(2);
									byte []buf = SymmetricKeyOps.decrypt((byte[])e.getObjContents().get(0), this.sessionKey, iv);
									int n = Integer.parseInt(new String(SymmetricKeyOps.decrypt((byte[])e.getObjContents().get(1), this.sessionKey, iv)));

									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write(buf, 0, (Integer) n);
										response = new Envelope("READY"); //Success
										output.writeObject(response);
										e = (Envelope)input.readObject();
									}

									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, groupIV, hashNum);
										response = new Envelope("OK"); //Success
									} else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
									}
									fos.close();
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {
					temp = e.getObjContents();
					encRemotePath = (byte[]) temp.get(0);
					encToken = (byte[]) temp.get(1);
					iv = (byte[]) temp.get(2);
					t = (Token) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt(encToken, this.sessionKey, iv));
					signedHash = SymmetricKeyOps.decrypt((byte[])temp.get(3), this.sessionKey, iv);

					if(!verifyToken(t, signedHash))
						e = new Envelope("FAIL");
					else {
						remotePath = new String(SymmetricKeyOps.decrypt(encRemotePath, this.sessionKey, iv));

						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_FILEMISSING");
							output.writeObject(e);
						} else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
							output.writeObject(e);
						} else {

							try {
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_NOTONDISK");
									output.writeObject(e);
								} else {
									FileInputStream fis = new FileInputStream(f);

									do {
										byte[] buf = new byte[4096];
										if (e.getMessage().compareTo("DOWNLOADF")!=0) {
											System.out.printf("Server error: %s\n", e.getMessage());
											break;
										}
										e = new Envelope("CHUNK");
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) {
											System.out.printf(".");
										} else if (n < 0) {
											System.out.println("Read error");
										}

										// Encrypt and send chunk
										spec = SymmetricKeyOps.getGCM();
										e.addObject(SymmetricKeyOps.encrypt(buf, this.sessionKey, spec));
										e.addObject(SymmetricKeyOps.encrypt(new Integer(n).toString().getBytes(), this.sessionKey, spec));
										e.addObject(spec.getIV());
										output.writeObject(e);

										e = (Envelope)input.readObject();
									} while (fis.available()>0);

									//If server indicates success, return the member list
									if(e.getMessage().compareTo("DOWNLOADF")==0) {

										e = new Envelope("EOF");
										ShareFile sFile = FileServer.fileList.getFile(remotePath);
										System.out.println("\n\nPath: " + remotePath + "\n");
										e.addObject(sFile.getIV());
										e.addObject(sFile.getHashNum());
										output.writeObject(e);

										e = (Envelope)input.readObject();
										if(e.getMessage().compareTo("OK")==0) {
											System.out.printf("File data upload successful\n");
										}
										else {
											System.out.printf("Upload failed: %s\n", e.getMessage());
										}
									} else {

										System.out.printf("Upload failed: %s\n", e.getMessage());
									}
								}
							}
							catch(Exception e1) {
								System.err.println("Error: " + e.getMessage());
								e1.printStackTrace(System.err);
							}
						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {
					temp = e.getObjContents();

					// Unload Envelope
					encRemotePath = (byte[]) temp.get(0);
					encToken = (byte[]) temp.get(1);
					iv = (byte[]) temp.get(2);
					signedHash = SymmetricKeyOps.decrypt((byte[])temp.get(3), this.sessionKey, iv);
					t = (Token) SymmetricKeyOps.byte2obj(SymmetricKeyOps.decrypt(encToken, this.sessionKey, iv));

					// Test if Token is Valid
					if(!verifyToken(t, signedHash))
						e = new Envelope("FAIL");
					else {
						remotePath = new String(SymmetricKeyOps.decrypt(encRemotePath, this.sessionKey, iv));

						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
						}
						else {

							try {
								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									e = new Envelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE");
								}
							}
							catch(Exception e1) {
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage());
							}
						}
					}
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT")) {
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(EOFException ex){

		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
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
	      pubSig.initVerify(this.groupServerPublicKey);
	      pubSig.update(hashedIdentifier);
	      boolean match = pubSig.verify(groupServerSignedHash);
	      System.out.println("Verifying User's Token.... " + match);
	      if(match) return true;

	    } catch (Exception e){}
	      return false;
	  }

}
