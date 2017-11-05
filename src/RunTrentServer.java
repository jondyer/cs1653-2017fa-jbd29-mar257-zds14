/* Driver program for Trent Server */

public class RunTrentServer {

	public static void main(String[] args) {
		if (args.length> 0) {
			try {
				TrentServer server = new TrentServer(Integer.parseInt(args[0]));
				server.start();
			} catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", TrentServer.SERVER_PORT);
			}
		} else {
			TrentServer server = new TrentServer();
			server.start();
		}
	}
}
