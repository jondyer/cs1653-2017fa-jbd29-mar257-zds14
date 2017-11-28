import java.util.ArrayList;


public class Envelope implements java.io.Serializable {

  /**
   *
   */
  private static final long serialVersionUID = -7726335089122193103L;
  private String msg;
  private ArrayList<Object> objContents = new ArrayList<Object>();
  private int sequenceNum;

  public Envelope(String text) {
    msg = text;
  }

  public Envelope() {
    msg = "";
  }

  public String getMessage() {
    return msg;
  }

  public void setMessage(String text) {
    msg = text;
  }

  public ArrayList<Object> getObjContents() {
    return objContents;
  }

  public void addObject(Object object) {
    objContents.add(object);
  }

  public void setSeq(int num) {
    this.sequenceNum = num;
  }

  public int getSeq() {
    return this.sequenceNum;
  }

}
