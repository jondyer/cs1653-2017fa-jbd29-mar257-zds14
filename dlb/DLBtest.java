import java.util.Scanner;
import java.io.*;
import java.util.ArrayList;


public class DLBtest {
  public static void main(String[] args) throws Exception {
    File file = new File("longpass.txt");
    BufferedReader bf = new BufferedReader(new FileReader(file));
    DLBtrie<Boolean> tr;
    tr = new DLBtrie<Boolean>();

    String line;
    long startTime = System.nanoTime();
    while((line = bf.readLine()) != null) {
      tr.insert(line, true);
    }

    long endTime = System.nanoTime();
    long duration = (endTime - startTime) / 1000000;
    System.out.println(duration + "ms\n");


    String test = "table23@";
    String test1 = "Password";
    startTime = System.nanoTime();
    if(tr.contains(test))
      System.out.println(test + " is forbidden.");
    else
      System.out.println(test + " is valid.");
    endTime = System.nanoTime();
    duration = (endTime - startTime) / 1000000;
    System.out.println(duration + "ms\n");

    startTime = System.nanoTime();
    if(tr.contains(test1))
      System.out.println(test1 + " is forbidden.");
    else
      System.out.println(test1 + " is valid.");
    endTime = System.nanoTime();
    duration = (endTime - startTime) / 1000000;
    System.out.println(duration + "ms\n");
  }


}
