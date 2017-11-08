import java.net.Socket;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class Server {

	protected int port;
	public String name;

	protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;

	protected KeyPairGenerator keyGenRSA;
	protected KeyPair keyPairRSA;
	protected PublicKey pub;
	protected PrivateKey priv;

	protected String keyFile;



	public Server(int _SERVER_PORT, String _serverName) {
		port = _SERVER_PORT;
		name = _serverName;
		keyFile = "KeyPair-" + port + ".bin";
	}

	public int getPort() {
		return port;
	}

	public String getName() {
		return name;
	}

	public boolean connect(final String server, final int port, boolean quiet) {
	    try {
	      // Creates a connection to server at the specified port
	      sock = new Socket(server, port);

	      // Creates Input / Output streams with the server we connected to
	      output = new ObjectOutputStream(sock.getOutputStream());
	      input = new ObjectInputStream(sock.getInputStream());
	    } catch(Exception e) {
	        System.err.println("Error: " + e.getMessage());
	        e.printStackTrace(System.err);
	        return false;
	    }

	    return isConnected();
	}

	public boolean isConnected() {
	    if (sock == null || !sock.isConnected())
	      return false;
	    else
	      return true;
	}

	public void disconnect()   {
	    if (isConnected()) {
	    	try {
		        Envelope message = new Envelope("DISCONNECT");
		        output.writeObject(message);
	    	}
	    	catch(Exception e) {
		        System.err.println("Error: " + e.getMessage());
		        e.printStackTrace(System.err);
	    	}
	    }
	}

	protected boolean registerServer(String TRENT_IP, int TRENT_PORT) {
		getKeyPair();

    if (!connect(TRENT_IP, TRENT_PORT, true)) return false;

    Envelope envelope = new Envelope("CSERV");
    envelope.addObject(pub);
    envelope.addObject(getPort());

    try {
	  	output.writeObject(envelope);
	    envelope = (Envelope)input.readObject();

		  if (envelope.getMessage().compareTo("OK")==0) {
		    System.out.printf("Server created successfully\n");
		  }
		  else {
		    System.out.printf("Server already exists...\n");
		    return false;
		  }
		} catch (IOException e1) {
		  e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
		  e1.printStackTrace();
		} finally {
		  disconnect();
		}

		return true;
	}

	protected void getKeyPair() {
		ObjectInputStream keyStream;

		// Open key file to get key pair
		try {
			FileInputStream fis = new FileInputStream(keyFile);
			keyStream = new ObjectInputStream(fis);
			keyPairRSA = (KeyPair)keyStream.readObject();
			pub = keyPairRSA.getPublic();
      priv = keyPairRSA.getPrivate();
		} catch(FileNotFoundException e) {
			System.out.println("KeyPair Does Not Exist. Creating KeyPair...");
			genKeyPair();
		} catch(IOException e) {
			System.out.println("Error reading from KeyPair file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e) {
			System.out.println("Error reading from KeyPair file");
			System.exit(-1);
		}
	}

	protected void genKeyPair() {
		Security.addProvider(new BouncyCastleProvider());

		try{
			keyGenRSA = KeyPairGenerator.getInstance("RSA", "BC");
		} catch(NoSuchAlgorithmException alg) {
			System.out.println(alg.getMessage());
		} catch(NoSuchProviderException prov) {
			System.out.println(prov.getMessage());
		}
        keyGenRSA.initialize(2048);
        keyPairRSA = keyGenRSA.generateKeyPair();

        ObjectOutputStream outStream;

		try {
			outStream = new ObjectOutputStream(new FileOutputStream(keyFile));
			outStream.writeObject(keyPairRSA);
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

        pub = keyPairRSA.getPublic();
        priv = keyPairRSA.getPrivate();
	}
}
