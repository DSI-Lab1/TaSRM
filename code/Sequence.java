import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Implementation of a sequence as a list of itemsets, where an itemset is a list of integers.
 */
public class Sequence {
	/** A sequence is a list of itemsets, 
	 * where an itemset is a list of integers
	 */
	private final List<List<Integer>> itemsets = new ArrayList<List<Integer>>();
	/** sequence id */
	private int id; 

	/**
	 * Constructor
	 * @param id the id of this sequence.
	 */
	public Sequence(int id) {
		this.id = id;
	}

	/**
	 * Add an itemset to this sequence.
	 * @param itemset An itemset (list of integers)
	 */
	public void addItemset(List<Integer> itemset) {
		itemsets.add(itemset);
	}

	/**
	 * Print this sequence to System.out.
	 */
	public void print() {
		System.out.print(toString());
	}

	/**
	 * Return a string representation of this sequence.
	 */
	public String toString() {
		StringBuilder r = new StringBuilder("");
		// for each itemset
		for (List<Integer> itemset : itemsets) {
			r.append('(');
			// for each item in the current itemset
			for (Integer item : itemset) {
				String string = item.toString();
				r.append(string);
				r.append(' ');
			}
			r.append(')');
		}

		return r.append("    ").toString();
	}
	
	/**
	 * Get the sequence ID of this sequence.
	 */
	public int getId() {
		return id;
	}

	/**
	 * Get the list of itemsets in this sequence.
	 * @return the list of itemsets.
	 */
	public List<List<Integer>> getItemsets() {
		return itemsets;
	}

	/**
	 * Get the itemset at a given position in this sequence.
	 * @param index the position
	 * @return the itemset as a list of integers.
	 */
	public List<Integer> get(int index) {
		return itemsets.get(index);
	}
	
	/**
	 * Get the size of this sequence (number of itemsets).
	 * @return the size (an integer).
	 */
	public int size() {
		return itemsets.size();
	}

	/**
	 * Make a copy of this sequence while removing some items
	 * that are infrequent with respect to a threshold minsup.
	 * @param mapSequenceID a map with key = item  value = a set of sequence ids containing this item
	 * @param relativeMinSup the minimum support threshold chosen by the user.
	 * @return a copy of this sequence except that item(s) with a support lower than minsup have been excluded.
	 */
	public Sequence cloneSequenceMinusItems(Map<Integer, Set<Integer>> mapSequenceID, double relativeMinSup) {
		// create a new sequence
		Sequence sequence = new Sequence(getId());
		// for each  itemset in the original sequence
		for(List<Integer> itemset : itemsets){
			// call a method to copy this itemset
			List<Integer> newItemset = cloneItemsetMinusItems(itemset, mapSequenceID, relativeMinSup);
			// add the copy to the new sequence
			if(newItemset.size() !=0){ 
				sequence.addItemset(newItemset);
			} 
		}
		return sequence; // return the new sequence
	}
	
	/**
	 * Make a copy of this sequence while removing some items
	 * that are infrequent with respect to a threshold minsup.
	 * @param mapSequenceID a map with key = item  value = a set of sequence  containing this item
	 * @param relativeMinSup the minimum support threshold chosen by the user.
	 * @return a copy of this sequence except that item(s) with a support lower than minsup have been excluded.
	 */
	public Sequence cloneSequenceMinusItems(double relativeMinSup, Map<Integer, Set<Sequence>> mapSequenceID) {
		// create a new sequence
		Sequence sequence = new Sequence(getId());
		// for each  itemset in the original sequence
		for(List<Integer> itemset : itemsets){
			// call a method to copy this itemset
			List<Integer> newItemset = cloneItemsetMinusItems(relativeMinSup, itemset, mapSequenceID);
			// add the copy to the new sequence
			if(newItemset.size() !=0){ 
				sequence.addItemset(newItemset);
			} 
		}
		return sequence; // return the new sequence
	}
	
	/**
	 * Make a copy of an itemset while removing some items
	 * that are infrequent with respect to a threshold minsup.
	 * @param mapSequenceID a map with key = item  value = a set of sequence  containing this item
	 * @param relativeMinsup the minimum support threshold chosen by the user.
	 * @param itemset the itemset
	 * @return a copy of this itemset except that item(s) with a support lower than minsup have been excluded.
	 */
	public List<Integer> cloneItemsetMinusItems(double relativeMinsup, List<Integer> itemset,Map<Integer, Set<Sequence>> mapSequenceID) {
		// create a new itemset
		List<Integer> newItemset = new ArrayList<Integer>();
		// for each item of the original itemset
		for(Integer item : itemset){
			// if the support is enough
			if(mapSequenceID.get(item).size() >= relativeMinsup){
				newItemset.add(item); // add it to the new itemset
			}
		}
		return newItemset; // return the new itemset.
	} 
	
	/**
	 * Make a copy of an itemset while removing some items
	 * that are infrequent with respect to a threshold minsup.
	 * @param mapSequenceID a map with key = item  value = a set of sequence ids containing this item
	 * @param minSupportAbsolute the minimum support threshold chosen by the user.
	 * @param itemset the itemset
	 * @return a copy of this itemset except that item(s) with a support lower than minsup have been excluded.
	 */
	public List<Integer> cloneItemsetMinusItems(List<Integer> itemset,Map<Integer, Set<Integer>> mapSequenceID, double minSupportAbsolute) {
		// create a new itemset
		List<Integer> newItemset = new ArrayList<Integer>();
		// for each item of the original itemset
		for(Integer item : itemset){
			// get the sed of sequences containing this item
			Set<Integer> sidSet = mapSequenceID.get(item);
			// if this set is not null (an infrequent item) and the support is higher than minsup...
			if(sidSet  !=null && sidSet.size() >= minSupportAbsolute){
				newItemset.add(item); // add it to the new itemset
			}
		}
		return newItemset; // return the new itemset.
	}

	
	public void remove(int i) {
		// TODO Auto-generated method stub
		this.itemsets.remove(i);
	} 

}
