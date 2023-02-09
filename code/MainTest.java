import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;

/**
 * @author Gengsen Huang, 2021
 * This test is for targeted sequential rule mining.
 * Part of the code for our project was taken from 
 * website SPMF ( https://www.philippe-fournier-viger.com/spmf/).
 * Please let me know if you find any bugs (hgengsen@gmail.com).
 */

public class MainTest {
	
	public static void main(String [] arg) throws IOException{
		String input = fileToPath("BIBLE.txt");  // the database
		String output = ".//output.txt";  // the path for saving the frequent itemsets found

		int minsup_relative = 300;
		double minconf = 0.5;
		TaSRM_V3 algo = new TaSRM_V3();
		
		// print minsup and minconf
		System.out.println("minsup: " + minsup_relative + " minconf :" + minconf);
		
		ArrayList<Integer> XQuery = new ArrayList<Integer>();
		ArrayList<Integer> YQuery = new ArrayList<Integer>();
		
		XQuery.add(8);
		XQuery.add(46);

		algo.runAlgorithm(input, output, minsup_relative, minconf, XQuery, YQuery);
		
		// print statistics
		algo.printStats();
	}
	
	public static String fileToPath(String filename) throws UnsupportedEncodingException{
		URL url = MainTest.class.getResource(filename);
		 return java.net.URLDecoder.decode(url.getPath(),"UTF-8");
	}
}
