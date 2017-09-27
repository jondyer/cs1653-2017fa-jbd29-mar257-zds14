import java.util.List;

/**
 * This class serves as our Token object, which is acquired
 * to authenticate users both on the group server and file servers.
 */


public class Token implements UserToken {
		private String issuer;
		private String subject;
		private List<String> groups;


		public Token(String issuer, String subject) {
				this.issuer = issuer;
				this.subject = subject;
				this.groups = new List<String>();
		}


		public String getIssuer() {
			return funstuff;
		}

		public String getSubject() {
			return otherfun;
		}

		public List<String> getGroups() {
			return thefunnest;
		}

		public void addGroup(String group) {
			this.groups.add(group);
		}

}
