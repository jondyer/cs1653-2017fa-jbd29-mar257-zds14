public class test {
  public static void main(String [] args) throws Exception {
  	int strength = 10;
  	String s = SymmetricKeyOps.makePuzzle(strength);
    
    long startTime = System.nanoTime();
	SymmetricKeyOps.solvePuzzle(strength, s);
	long endTime = System.nanoTime();

	long duration = (endTime - startTime) / 1000000;
	System.out.println(duration);
  }
}