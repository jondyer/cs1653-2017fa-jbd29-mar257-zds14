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

	protected KeyPairGenerator keyGenRSA;
	protected KeyPair keyPairRSA;
	protected PublicKey pub;
	protected PrivateKey priv;

	protected String keyFile;

	abstract void start();

	// TODO: Include D-H CONSTANTS

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
