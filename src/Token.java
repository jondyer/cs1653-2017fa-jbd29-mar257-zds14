/**
 * This class serves as our Token object, which is acquired
 * to authenticate users both on the group server and file servers.
 */

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class Token implements UserToken, java.io.Serializable {

    private static final long serialVersionUID = -5699986336399821572L;
    private String issuer;        // GroupServer
    private String subject;       // Person whom the token belongs to
    private List<String> groups;  // Groups belonged to (for a full token) || Groups requested for the session (partial token)
    private String address;       // Address ("ipadress:port") of the fileserver to which token will be presented to

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

    public String getAddress() {
      return this.address;
    }

    public void setAddress(String address) {
      this.address = address;
    }

    public List<String> getGroups() {
      List<String> gr = new ArrayList<String>(groups);
      return gr;
    }

    public void addGroup(String group) {
      this.groups.add(group);
      Collections.sort(groups, String.CASE_INSENSITIVE_ORDER);
    }

    /**
     * Builds a unique identifier of the issuer, subject, groups, and fileserver address used for verifying signature in other classes, where the order of groups in the token (should be) arbitrary
     * @return String identifier of token.
     */
    public String getIdentifier() {
      StringBuilder b = new StringBuilder();
      b.append(this.issuer + ":");
      b.append(this.subject + ":");
      for(String s : this.groups)
        b.append(s + ":");
      b.append(this.address);
      return b.toString();
    }

}
