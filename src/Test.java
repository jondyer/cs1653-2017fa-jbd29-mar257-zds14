public class Test extends GroupClient implements GroupClientInterface {

	public static void main(String[] args) {

		GroupClient client = new GroupClient();
		client.connect("localhost", 8765);

		UserToken token = client.getToken("zach");
		System.out.println(token.getSubject());
		client.disconnect();
	}
}