import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected int sequence = 0;

	public boolean connect(final String server, final int port) {
		System.out.println("Attempting to connect...");

		try {
			// Creates a connection to server at the specified port
			sock = new Socket(server, port);
			System.out.println("Connected to " + server + " on port " + port);

			// Creates Input / Output streams with the server we connected to
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());

<<<<<<< HEAD
				System.out.println("\n" + port + " is doing a puzzle!\n");
				doPuzzle();

=======
			if(port == 4321 || port == 8765) {
				System.out.println("Doing a puzzle for "+ port + "!\n");
				doPuzzle();
			}
>>>>>>> e002d6eeb15e4792f3c0d72c058ad65638c54bdf


		} catch(Exception e) {
		    System.err.println("Error: " + e.getMessage());
		    e.printStackTrace(System.err);
		    return false;
		}

		return isConnected();
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

	private void doPuzzle() throws Exception {
		Envelope e = (Envelope)input.readObject();
		int strength = (int) e.getObjContents().get(0);
		String puzzle = (String) e.getObjContents().get(1);
		String solution = SymmetricKeyOps.solvePuzzle(strength, puzzle);
		Envelope response = new Envelope("OK");
		response.addObject(solution);
		output.writeObject(response);

		if(!isConnected()) {
			System.exit(1);
		}
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
}
