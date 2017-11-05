/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static FileList fileList;

	private Socket sock;
	private ObjectOutputStream output;
	private ObjectInputStream input;

	public FileServer() {
		super(SERVER_PORT, "FilePile");
		registerServer();
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
		registerServer();
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

	public void disconnect()	 {
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

	private boolean registerServer() {
		getKeyPair();

        // TODO: Connect to Trent
        if (!connect("127.0.0.1", 4444, true)) return false;

        Envelope env = new Envelope("CSERV");
        env.addObject(pub);
        env.addObject(getPort());

        try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File Server created successfully\n");
			}
			else {
				System.out.printf("Error creating File Server\n");
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
		return true;
	}

	public void start() {
		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		} catch(FileNotFoundException e) {
			System.out.println("FileList Does Not Exist. Creating FileList...");
			fileList = new FileList();
		} catch(IOException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		File file = new File("shared_files");

		 if (file.mkdir())
			 System.out.println("Created new shared_files directory");
		 else if (file.exists())
			 System.out.println("Found shared_files directory");
		 else
			 System.out.println("Error creating shared_files directory");


		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;

		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running) {
				sock = serverSock.accept();
				thread = new FileThread(sock);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves the file list
class ShutDownListenerFS implements Runnable {

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try {
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread {

	public void run() {
		do {
			try {

				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;

				try {
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
				}
				catch(Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
