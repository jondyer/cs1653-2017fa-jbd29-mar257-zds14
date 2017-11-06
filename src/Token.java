/**
 * This class serves as our Token object, which is acquired
 * to authenticate users both on the group server and file servers.
 */

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

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
        Collections.sort(groups, String.CASE_INSENSITIVE_ORDER);
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
      Collections.sort(groups, String.CASE_INSENSITIVE_ORDER);
    }

    public String getIdentifier() {
      StringBuilder b = new StringBuilder();
      b.append(issuer + ":");
      b.append(subject + ":");
      for(String s : groups)
        b.append(s + ":");
      return b.toString();
    }

}
