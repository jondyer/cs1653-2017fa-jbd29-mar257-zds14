/**
 * This class serves as our Token object, which is acquired
 * to authenticate users both on the group server and file servers.
 */

import java.util.List;
import java.util.ArrayList;


public class Token implements UserToken, java.io.Serializable {

    private static final long serialVersionUID = -5699986336399821572L;
    private String issuer;
    private String subject;
    private List<String> groups;


    public Token(String issuer, String subject) {
        this.issuer = issuer;
        this.subject = subject;
        this.groups = new ArrayList<String>();
    }

    public Token(String issuer, String subject, ArrayList<String> groups) {
        this.issuer = issuer;
        this.subject = subject;
        this.groups = groups;
    }

    public String getIssuer() {
      return issuer;
    }

    public String getSubject() {
      return subject;
    }

    public List<String> getGroups() {
      return groups;
    }

    public void addGroup(String group) {
      this.groups.add(group);
    }

}
