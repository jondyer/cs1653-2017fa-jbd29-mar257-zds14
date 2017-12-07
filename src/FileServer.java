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
import java.net.InetAddress;
import java.time.LocalDateTime;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static int TRENT_PORT = 4444;
	public static String TRENT_IP = "127.0.0.1";
	public static FileList fileList;
	public PublicKey groupServerPublicKey;


	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}


  public void start(String[] args) {
    // Overwrote server.start() because if no user file exists, initial admin account needs to be created
    if(args.length >= 2)      // just the Trent IP
      TRENT_IP = args[1];
    if(args.length >= 3)      // IP and port
      TRENT_PORT = Integer.parseInt(args[2]);

    registerServer(TRENT_IP, TRENT_PORT);

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
				LocalDateTime now = LocalDateTime.now();
				String client = sock.getInetAddress().getHostAddress();

				// If the address has already visited, check the map for last time it visited. If not, add it to the map.
				if(accessMap.keySet().contains(client)) {

					// Compare time of last visited to now
					LocalDateTime lastConnection = accessMap.get(client);
					if(now.isAfter(lastConnection.plusMinutes(10))) { // Last connection was longer than ten minutes ago, reset difficulty
						difficultyMap.replace(client, 0);
					} else {	// Make puzzle harder
						difficultyMap.replace(client, difficultyMap.get(client)+1);
					}
					accessMap.replace(client, now);	// Update last connection time to now

				} else {	// New Connection
					accessMap.put(client, now);
					difficultyMap.put(client, 0);
				}
				thread = new FileThread(sock, this);
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
