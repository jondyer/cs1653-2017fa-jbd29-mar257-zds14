public class test {
  public static void main(String [] args) throws Exception {
  	//int strength = 1;
  	for(int strength = 1; strength <= 15; strength++) {
  		System.out.println("Strength: " + strength);
	  	//String s = SymmetricKeyOps.makePuzzle(strength);
	  	
	  	String append = "";
	  	for (int i = 1; i < strength; i++) append += "0";
	  	String s = new String(SymmetricKeyOps.hash("1" + append), "UTF-8");
	    
	    long startTime = System.nanoTime();
		SymmetricKeyOps.solvePuzzle(strength, s);
		long endTime = System.nanoTime();

		long duration = (endTime - startTime) / 1000000;
		System.out.println(duration + "ms\n");
	}
  }
}