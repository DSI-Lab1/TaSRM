import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;



/**
 * Implementation of a sequence database, where each sequence is implemented
 * as a list of integers and should have a unique id.
 */
public class SequenceDatabase {

	// variable that contains the sequences of this database
	private final List<Sequence> sequences = new ArrayList<Sequence>();

	/**
	 * Method to load a sequence database from a text file in SPMF format.
	 * @param path  the input file path.
	 * @throws IOException exception if error while reading the file.
	 */
	public void loadFile(String path) throws IOException {
		String thisLine; // variable to read each line.
		BufferedReader myInput = null;
		try {
			FileInputStream fin = new FileInputStream(new File(path));
			myInput = new BufferedReader(new InputStreamReader(fin));
			// for each line until the end of the file
			int i=0;
			while ((thisLine = myInput.readLine()) != null) {
				// if the line is not a comment, is not empty or is not other
				// kind of metadata
				if (thisLine.isEmpty() == false &&
						thisLine.charAt(0) != '#' && thisLine.charAt(0) != '%'
						&& thisLine.charAt(0) != '@') {
					// split this line according to spaces and process the line

					addSequence(thisLine.split(" "));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (myInput != null) {
				myInput.close();
			}
		}
	}
	
	/**
	 * Method to process a line from the input file
	 * @param tokens A list of tokens from the line (which were separated by spaces in the original file).
	 */
	void addSequence(String[] tokens) { 
		// create a new Sequence to store the sequence
		Sequence sequence = new Sequence(sequences.size());
		// create a list of strings for the first itemset.
		
		List<Integer> itemset = new ArrayList<Integer>();
		// for each token in this line
		for (String token : tokens) {
			// if the token start with "<", it indicates a timestamp. 
			// We just ignore it because algorithms that use this class
			// don't need it.
			if (token.codePointAt(0) == '<') { 
				// we ignore
			} 
			// if the token is -1, it means that we reached the end of an itemset.
			else if (token.equals("-1")) { 
				// add the current itemset to the sequence
				sequence.addItemset(itemset);
				// create a new itemset
				itemset = new ArrayList<Integer>();
			} 
			// if the token is -2, it means that we reached the end of 
			// the sequence.
			else if (token.equals("-2")) { 
				// we add it to the list of sequences
				sequences.add(sequence);
			} else { 
				// otherwise it is an item.
				// we parse it as an integer and add it to 
				// the current itemset.
				itemset.add(Integer.parseInt(token));
			}
		}
	}

	/**
	 * Method to add a sequence to this sequence database
	 * @param sequence A sequence of type "Sequence".
	 */
	public void addSequence(Sequence sequence) {
		sequences.add(sequence);
	}
	
	/**
	 * Print this sequence database to System.out.
	 */
	public void print() {
		System.out.println("============  SEQUENCE DATABASE ==========");
		for (Sequence sequence : sequences) { // pour chaque objet
			System.out.print(sequence.getId() + ":  ");
			sequence.print();
			System.out.println("");
		}
	}
	
	/**
	 * Print statistics about this database.
	 */
	public void printDatabaseStats() {
		System.out.println("============  STATS ==========");
		System.out.println("Number of sequences : " + sequences.size());
		
		// Calculate the average size of sequences in this database
		long size = 0;
		for(Sequence sequence : sequences){
			size += sequence.size();
		}
		double meansize = ((float)size) / ((float)sequences.size());
		System.out.println("mean size" + meansize);
	}

	/**
	 * Return a string representation of this sequence database.
	 */
	public String toString() {
		StringBuilder r = new StringBuilder();
		// for each sequence
		for (Sequence sequence : sequences) { 
			r.append(sequence.getId());
			r.append(":  ");
			r.append(sequence.toString());
			r.append('\n');
		}
		return r.toString();
	}
	
	/**
	 * Get the sequence count in this database.
	 * @return the sequence count.
	 */
	public int size() {
		return sequences.size();
	}
	
	/**
	 * Get the sequences from this sequence database.
	 * @return A list of sequences (Sequence).
	 */
	public List<Sequence> getSequences() {
		return sequences;
	}

	/**
	 * Get the list of sequence IDs for this database.
	 * @return A set containing the sequence IDs of sequence in this
	 * database.
	 */
	public Set<Integer> getSequenceIDs() {
		// create a set
		Set<Integer> set = new HashSet<Integer>();
		// for each sequence
		for (Sequence sequence : getSequences()) {
			set.add(sequence.getId()); // add the id to the set.
		}
		return set; // return the set.
	}

	
	// remove sequence
	public void remove(int t) {
		// TODO Auto-generated method stub
		sequences.remove(t);
	}

}
