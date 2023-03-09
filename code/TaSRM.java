import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * TaSRM: Targeted sequential rule mining
 * This is the implementation of the TaSRM_{V3} algorithm.
 * Using UTP, UIP, URP, UEIP, leftCount, and rightCount.
 * Part of the code is from RuleGrowth (RuleGrowth: Mining Sequential Rules Common to Several Sequences by Pattern-Growth.).
 * 
 * @author Gengsen Huang, 2021
 */

public class TaSRM_V3 {
	//*** for statistics ***/
	
	/** start time of latest execution */
	long timeStart = 0;  
	
	/**  end time of latest execution */
	long timeEnd = 0;  
	
	/** number of rules generated */
	int ruleCount; 
	/** number of target rules*/
	int validCount = 0;
	
	//*** parameters ***/
	/** minimum confidence */
	double minConfidence;
	
	/** minimum support */
	int minsuppRelative;
	
	/** this is the sequence database */
	SequenceDatabase database;
	
	/*** internal variables 
	// This map contains for each item (key) a map of occurences (value).
	// The map of occurences associates to sequence ID (key), an occurence of the item (value). */
	Map<Integer,  Map<Integer, Occurence>> mapItemCount;  // item, <tid, occurence>

	/** object to write the output file */
	BufferedWriter writer = null; 

	/** Used by the debug mode to keep all rules found */
	static List<Rule> allRulesFoundForDEBUG = new ArrayList<Rule>();
	
	/** If true the debug mode will be used */
	boolean DEBUG = false;
	
	/**  the maximum size of the antecedent of rules (optional) */
	int maxAntecedentSize = Integer.MAX_VALUE;
	
	/** the maximum size of the consequent of rules (optional) */
	int maxConsequentSize = Integer.MAX_VALUE;
	
	// query rule
   	ArrayList<Integer> XQuery = new ArrayList<Integer>();
   	ArrayList<Integer> YQuery = new ArrayList<Integer>(); 
    
    	// a map to record sid and matching position of a sequence
    	// HashMap<Integer, Pair<Integer, Integer>> matchPosMap = new HashMap<Integer, Pair<Integer, Integer>>(); // not pair class
    	HashMap<Integer, ArrayList<Integer>> matchPosMap = new HashMap<Integer, ArrayList<Integer>>();
    
    	// leftCount and rightCount
    	HashMap<Integer, Integer> leftCount = new HashMap<Integer, Integer>();
    	HashMap<Integer, Integer> rightCount = new HashMap<Integer, Integer>();
    
    	// expand count
    	double expandCount = 0;
    
    	// strategy
    	boolean UIP = true;
    	boolean URP = true;
    	boolean UEIP = true;

	/**
	 * Default constructor
	 */
	public TaSRM_V3() {
	}


	/**
	 * The main method to run the algorithm
	 */
	public void runAlgorithm(double minSupport, double minConfidence, String input, String output, ArrayList<Integer> xQuery, ArrayList<Integer> yQuery) throws IOException {
		try {
			// read the input database
			database = new SequenceDatabase(); 
			database.loadFile(input);
		} catch (Exception e) {
			e.printStackTrace();
		}
		// convert minimum support to an absolute minimum support (integer)
		this.minsuppRelative = (int) Math.ceil(minSupport * database.size());
		
		// run the algorithm  with the just calculated absolute minimum support
		runAlgorithm(input, output, minsuppRelative, minConfidence, xQuery, yQuery);
	}
	
	/**
	 * The main method to run the algorithm
	 * @param relativeMinsup : the minimum support as an integer value (a relative minimum support)
	 * @param minConfidence : the minimum confidence threshold
	 * @param input : an input file path of a sequence database
	 * @param output : a file path for writing the output file containing the seq. rules.
	 * @param xQuery : XQuery of the query rule
	 * @param yQuery : YQuery of the query rule 
	 * @exception IOException if error reading/writing files
	 */
	public void runAlgorithm(String input, String output, int relativeMinsup, double minConfidence, ArrayList<Integer> xQuery, ArrayList<Integer> yQuery) throws IOException {
		// save the minimum confidence parameter
		this.minConfidence = minConfidence;
		// reinitialize the number of rules found
		ruleCount = 0;
		validCount = 0;
		// save query rule
		this.XQuery = xQuery;
		this.YQuery = yQuery;
		
		// print
		System.out.print("Query rule: ");
		for(int i = 0; i < XQuery.size(); i++) {
			System.out.print(XQuery.get(i) + " ");	
		}
		System.out.print("-> ");
		for(int i = 0; i < YQuery.size(); i++) {
			System.out.print(YQuery.get(i) + " ");	
		}
		System.out.print("\n");
		
		// if the database was not loaded, then load it.
		if(database == null){
			try {
				database = new SequenceDatabase(); 
				database.loadFile(input);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		// reset the stats for memory usage
		MemoryLogger.getInstance().reset();

		// prepare the object for writing the output file
		writer = new BufferedWriter(new FileWriter(output)); 
		
		// if minsup is 0, set it to 1 to avoid generating
		// rules not in the database
		this.minsuppRelative =  relativeMinsup;
		if(this.minsuppRelative == 0){ // protection
			this.minsuppRelative = 1;
		}

		// save the start time
		timeStart = System.currentTimeMillis(); // for stats
		
		// Using UTP to filter the original database.
		filterDatabase(database);
		System.out.println("database size: "+ database.size());
		
		// Using UIP to filter unpromising item.
		if(UIP) {
			filterUnpromisingItem(database);
		}
		
		// Initialize leftCount and rightCount
		for(Map.Entry<Integer, Map<Integer, Occurence>> entry : mapItemCount.entrySet()) {
			Map<Integer, Occurence> OccurenceI = entry.getValue();
			Integer item = entry.getKey();
			int ll = 0, rr = 0;
			for(Map.Entry<Integer, Occurence> entryI : OccurenceI.entrySet()) {
				Integer sid = entryI.getKey();
				Occurence OccurenceIJ = entryI.getValue();
				if(OccurenceIJ.firstItemset < matchPosMap.get(sid).get(1)) {
					ll++;
				}
				if(OccurenceIJ.lastItemset > matchPosMap.get(sid).get(0)) {
					rr++;
				}
			}
			leftCount.put(item, ll);
			rightCount.put(item, rr);
		}
		
		
		// Remove infrequent items from the database in one database scan.
		// Then perform another database scan to count the
		// the support of each item in the same database scan 
		// and their occurrences.
		removeItemsThatAreNotFrequent(database);	
		
		
		
		// Put frequent items in a list.
		List<Integer> listFrequents = new ArrayList<Integer>();
		// for each item
		for(Entry<Integer,Map<Integer, Occurence>> entry : mapItemCount.entrySet()){
			// if it is frequent
			if(entry.getValue().size() >= minsuppRelative){
				// add it to the list
				listFrequents.add(entry.getKey());
			}
		}
		
		
		// We will now try to generate rules with one item in the
		// antecedent and one item in the consequent using
		// the frequent items.

		// For each pair of frequent items i  and j such that i != j
		for(int i=0; i< listFrequents.size(); i++){
			// get the item I and its map of occurences
			Integer intI = listFrequents.get(i);
			Map<Integer, Occurence> occurencesI = mapItemCount.get(intI);
			// get the tidset of item I
			Set<Integer> tidsI = occurencesI.keySet();

			
			for(int j=i+1; j< listFrequents.size(); j++){
				// get the item j and its map of occurences
				Integer intJ = listFrequents.get(j);
				Map<Integer,Occurence> occurencesJ = mapItemCount.get(intJ);
				// get the tidset of item J
				Set<Integer> tidsJ = occurencesJ.keySet();
		
				// initialize the sets
				Set<Integer> tidsIJ = new HashSet<Integer>();  // tidset of  I -->J  
				Set<Integer> tidsJI = new HashSet<Integer>(); // tidset of J-->I

				boolean pruneIJ = false;
				boolean pruneJI = false;
				if(URP) {
					if((XQuery.size() > 0 && intI > XQuery.get(0)) || (YQuery.size() > 0 && intJ > YQuery.get(0))) {
						pruneIJ = true;
					}
					if((XQuery.size() > 0 && intJ > XQuery.get(0)) || (YQuery.size() > 0 && intI > YQuery.get(0))) {
						pruneJI = true;
					}
				}
				
				if(leftCount.get(intI) < minsuppRelative || rightCount.get(intJ) < minsuppRelative) {
					pruneIJ = true;
				}
				if(leftCount.get(intJ) < minsuppRelative || rightCount.get(intI) < minsuppRelative) {
					pruneJI = true;
				}
				
				if(pruneJI && pruneIJ) {
					continue;
				}
				
				for(Entry<Integer, Occurence> entryOccI : occurencesI.entrySet()){
					// get the occurence of J in the same sequence
					Occurence occJ = occurencesJ.get(entryOccI.getKey());
					// if J appears in that sequence
					if(occJ !=  null){
						// if J appeared before I in that sequence,
						// then we put this tid in the tidset of  J-->I
						if(!pruneJI && occJ.firstItemset < entryOccI.getValue().lastItemset){
							if(URP) {
								if(occJ.firstItemset < matchPosMap.get(entryOccI.getKey()).get(1) && 
										entryOccI.getValue().lastItemset > matchPosMap.get(entryOccI.getKey()).get(0)) {
									tidsJI.add(entryOccI.getKey());
								}
							}else{
								tidsJI.add(entryOccI.getKey());
							}
						}
						// if I appeared before J in that sequence,
						// then we put this tid in the tidset of  I-->J
						if(!pruneIJ && entryOccI.getValue().firstItemset < occJ.lastItemset){
							if(URP) {
								if(entryOccI.getValue().firstItemset < matchPosMap.get(entryOccI.getKey()).get(1) && 
										occJ.lastItemset > matchPosMap.get(entryOccI.getKey()).get(0)) {
									tidsIJ.add(entryOccI.getKey());
								}
							}else{
								tidsIJ.add(entryOccI.getKey());
							}
						}
					}
				}
				
				// create rule IJ
				if(!pruneIJ && tidsIJ.size() >= minsuppRelative){
					// calculate the confidence of I ==> J
					double confIJ = ((double)tidsIJ.size()) / occurencesI.size();

					// create itemset of the rule I ==> J
					int[] itemsetI = new int[1];
					itemsetI[0]= intI;
					int[] itemsetJ = new int[1];
					itemsetJ[0]= intJ;
					
					// two matching flag for UEIP
					int xMatch = 0;
					int yMatch = 0;
					
					if(XQuery.size() > 0 && XQuery.get(0).equals(intI)) {
						xMatch++;
					}
					if(YQuery.size() > 0 && YQuery.get(0).equals(intJ)) {
						yMatch++;
					}	
					
					// if the confidence is high enough, save the rule
					if(xMatch == XQuery.size() && yMatch == YQuery.size() && confIJ >= minConfidence){
						saveRule(tidsIJ, confIJ, itemsetI, itemsetJ);
						if(DEBUG) {
							Rule rule = new Rule(itemsetI, itemsetJ, tidsI, tidsJ, tidsIJ, occurencesI, occurencesJ);
							allRulesFoundForDEBUG.add(rule);
						}
					}

	
					// recursive call to try to expand the rule on the left and
					// right sides
					if(yMatch == YQuery.size() && itemsetI.length < maxAntecedentSize) {
						expandLeft(itemsetI, itemsetJ, tidsI, tidsIJ, occurencesJ, xMatch);
					}
					if(itemsetJ.length < maxConsequentSize) {
						expandRight(itemsetI, itemsetJ, tidsI, tidsJ, tidsIJ, occurencesI, occurencesJ, xMatch, yMatch);
					}
				}
					
				// check if J ==> I has enough common tids
				// If yes, we create the rule J ==> I
				if(!pruneJI && tidsJI.size() >= minsuppRelative){
					// create itemset of the rule J ==> I
					int[] itemsetI = new int[1];
					itemsetI[0]= intI;
					int[] itemsetJ = new int[1];
					itemsetJ[0]= intJ;
					
					// two matching flag for UEIP
					int xMatch = 0;
					int yMatch = 0;
					
					if(XQuery.size() > 0 && XQuery.get(0).equals(intJ)) {
						xMatch++;
					}
					if(YQuery.size() > 0 && YQuery.get(0).equals(intI)) {
						yMatch++;
					}
					
					// calculate the confidence
					double confJI = ((double)tidsJI.size()) / occurencesJ.size();
					
					// if the confidence is high enough, save the rule
					if(xMatch == XQuery.size() && yMatch == YQuery.size() && confJI >= minConfidence){
						saveRule(tidsJI, confJI, itemsetJ, itemsetI);
						if(DEBUG) {
							Rule rule = new Rule(itemsetJ, itemsetI, tidsJ,  tidsI, tidsJI, occurencesJ, occurencesI);
							allRulesFoundForDEBUG.add(rule);
						}
					}
					
					// recursive call to try to expand the rule on the left and
					// right sides
					if(itemsetI.length < maxConsequentSize) {
						expandRight(itemsetJ, itemsetI, tidsJ,  tidsI, tidsJI, occurencesJ, occurencesI, xMatch, yMatch);
					}
					if(yMatch == YQuery.size() &&itemsetJ.length < maxAntecedentSize) {
						expandLeft(itemsetJ, itemsetI, tidsJ, tidsJI, occurencesI, xMatch);
					}
				}
			}
		}
		
		// CHECK FOR REDUNDANT RULES
		if(DEBUG) {
			for(int i=0; i < allRulesFoundForDEBUG.size(); i++) {
				for(int j=i+1; j < allRulesFoundForDEBUG.size(); j++) {
					Rule rule1 = allRulesFoundForDEBUG.get(i);
					Rule rule2 = allRulesFoundForDEBUG.get(j);
					Arrays.sort(rule1.itemsetI);
					Arrays.sort(rule1.itemsetJ);
					Arrays.sort(rule2.itemsetI);
					Arrays.sort(rule2.itemsetJ);
					if(Arrays.equals(rule1.itemsetI, rule2.itemsetI) &&
							Arrays.equals(rule1.itemsetJ, rule2.itemsetJ)) {
						throw new RuntimeException(" DUPLICATE RULES FOUND");
					}
				}
			}
			
		}
		// save end time
		timeEnd = System.currentTimeMillis(); 
		
		// close the file
		writer.close();
		
		// after the algorithm ends, we don't need a reference to the database anymore.
		database = null;
	}


	/**
	 * Save a rule I ==> J to the output file
	 * @param tidsIJ the tids containing the rule
	 * @param confIJ the confidence
	 * @param itemsetI the left part of the rule
	 * @param itemsetJ the right part of the rule
	 * @throws IOException exception if error writing the file
	 */
	private void saveRule(Set<Integer> tidsIJ, double confIJ, int[] itemsetI, int[] itemsetJ) throws IOException {
		// increase the number of rule found
		ruleCount++;
		
		// increase the number of target rule found
		validCount++;
		
		// create a string buffer
		StringBuilder buffer = new StringBuilder();
		
		// write itemset 1 (antecedent)
		for(int i=0; i<itemsetI.length; i++){
			buffer.append(itemsetI[i]);
			if(i != itemsetI.length -1){
				buffer.append(",");
			}
		}
		
		// write separator
		buffer.append(" ==> ");
		
		// write itemset 2  (consequent)
		for(int i=0; i<itemsetJ.length; i++){
			buffer.append(itemsetJ[i]);
			if(i != itemsetJ.length -1){
				buffer.append(",");
			}
		}
		// write support
		buffer.append(" #SUP: ");
		buffer.append(tidsIJ.size());
		// write confidence
		buffer.append(" #CONF: ");
		buffer.append(confIJ);
		writer.write(buffer.toString());
		writer.newLine();
	}


	/**
	 * This method search for items for expanding left side of a rule I --> J 
	 * with any item c. This results in rules of the form I U�{c} --> J. The method makes sure that:
	 *   - c  is not already included in I or J
	 *   - c appear at least minsup time in tidsIJ before last occurence of J
	 *   - c is lexically bigger than all items in I
	 * @throws IOException 
	 */
    private void expandLeft(int [] itemsetI, int[] itemsetJ, Collection<Integer> tidsI, 
    						Collection<Integer> tidsIJ, 
    						Map<Integer, Occurence> occurencesJ,
    						int xMatch) throws IOException {    
    	expandCount++;
    	
    	// The following map will be used to count the support of each item
    	// c that could potentially extend the rule.
    	// The map associated a set of tids (value) to an item (key).
    	Map<Integer, Set<Integer>> frequentItemsC  = new HashMap<Integer, Set<Integer>>();  
    	
    	// We scan the sequence where I-->J appear to search for items c 
    	// that we could add to generate a larger rule  IU{c} --> J
    	int left = tidsIJ.size();  // the number of tid containing I-->J
    	
    	// For each tid of sequence containing I-->J
    	for(Integer tid : tidsIJ){
    		// get the sequence and occurences of J in that sequence
    		Sequence sequence = database.getSequences().get(tid);
			Occurence end = occurencesJ.get(tid);
			
			int endPos = end.lastItemset;
			if(UEIP) {
				if(endPos >= matchPosMap.get(tid).get(1)) {
					endPos = matchPosMap.get(tid).get(1);
				}
			}
			
			// for each itemset before the last occurence of J in that sequence
itemLoop:	for(int k=0; k < endPos; k++){
				List<Integer> itemset = sequence.get(k);
				// for each item c in that itemset
				for(int m=0; m < itemset.size(); m++){
					Integer itemC = itemset.get(m);
					
					// We will consider if we could create a rule IU{c} --> J
					// If lexical order is not respected or c is included in the rule already,
					// then we cannot so return.
					if(containsLEXPlus(itemsetI, itemC) ||  containsLEX(itemsetJ, itemC)){
						continue;
					}
					
					// UEIP
					if(UEIP && xMatch < XQuery.size() && XQuery.get(xMatch) < itemC) {
						continue;
					}
					
					// countMap
					if(leftCount.get(itemC) < minsuppRelative) {
						continue;
					}
					
					
					// Otherwise, we get the tidset of "c" 
					Set<Integer> tidsItemC = frequentItemsC.get(itemC);
					
					// if this set is not null, which means that "c" was not seen yet
					// when scanning the sequences from I==>J
					
					if(tidsItemC == null){ 
						// if there is less tids left in the tidset of I-->J to be scanned than
						// the minsup, we don't consider c anymore because  IU{c} --> J
						// could not be frequent
						if(left < minsuppRelative){
							continue;
						}	
					// if "c" was seen before but there is not enough sequences left to be scanned
					// to allow IU{c} --> J to reach the minimum support threshold
					}else if(tidsItemC.size() + left < minsuppRelative){
						// remove c and continue the loop of items
						frequentItemsC.remove(itemC);
						continue;
					}
					// otherwise, if we did not see "c" yet, create a new tidset for "c"
					if(tidsItemC == null){
						tidsItemC = new HashSet<Integer>(tidsIJ.size());
						frequentItemsC.put(itemC, tidsItemC);
					}
					// add the current tid to the tidset of "c"
					tidsItemC.add(tid);				
				}
			}
			left--;  // decrease the number of sequences left to be scanned
		}
    	
     	// For each item c found, we create a rule	IU{c} ==> J
    	for(Entry<Integer, Set<Integer>> entry : frequentItemsC.entrySet()){
    		Integer itemC = entry.getKey();
    		// get the tidset IU{c} ==> J
    		Set<Integer> tidsIC_J = entry.getValue();
    		
    		// if the support of IU{c} ==> J is enough 
    		if(tidsIC_J.size() >= minsuppRelative){ 
    			
    			// Calculate tids containing IU{c} which is necessary
    			// to calculate the confidence
    			Set<Integer> tidsIC = new HashSet<Integer>(tidsI.size());
    	    	for(Integer tid: tidsI){
    	    		if(mapItemCount.get(itemC).containsKey(tid)){
    	    			tidsIC.add(tid);
    	    		}
    	    	}
    			
    			// Create rule and calculate its confidence of IU{c} ==> J 
    	    	// defined as:  sup(IU{c} -->J) /  sup(IU{c})			
				double confIC_J = ((double)tidsIC_J.size()) / tidsIC.size();
				// create the itemset IU{c}
				int [] itemsetIC = new int[itemsetI.length+1];
				System.arraycopy(itemsetI, 0, itemsetIC, 0, itemsetI.length);
				itemsetIC[itemsetI.length] = itemC;
				
				// UEIP
				int newxMatch = xMatch;
				if(xMatch < XQuery.size() && XQuery.get(xMatch).equals(itemC)) {
					newxMatch++;
				}
				
				// if the confidence is high enough, then it is a valid rule
				if(newxMatch == XQuery.size() && confIC_J >= minConfidence){
					// save the rule
					saveRule(tidsIC_J, confIC_J, itemsetIC, itemsetJ);
					if(DEBUG) {
						Rule newRule = new Rule(itemsetIC, itemsetJ, tidsIC, null, tidsIC_J, null, occurencesJ);
						allRulesFoundForDEBUG.add(newRule);
					}
				}
				
				// recursive call to expand left side of the rule
				if(itemsetI.length < maxAntecedentSize) {
					expandLeft(itemsetIC, itemsetJ, tidsIC, tidsIC_J, occurencesJ, newxMatch);
				}
    		}
    	}
    	// check the memory usage
    	MemoryLogger.getInstance().checkMemory();
	}
    
	/**
	 * This method search for items for expanding left side of a rule I --> J 
	 * with any item c. This results in rules of the form I --> J U�{c}. The method makes sure that:
	 *   - c  is not already included in I or J
	 *   - c appear at least minsup time in tidsIJ after the first occurence of I
	 *   - c is lexically bigger than all items in J
	 * @param yMatch 
	 * @param xMatch 
	 * @throws IOException 
	 */
    private void expandRight(int [] itemsetI, int []itemsetJ,
							Set<Integer> tidsI, 
    						Collection<Integer> tidsJ, 
    						Collection<Integer> tidsIJ, 
    						Map<Integer, Occurence> occurencesI,
    						Map<Integer, Occurence> occurencesJ, int xMatch, int yMatch) throws IOException {
    	
    	expandCount++;
    	
    	// The following map will be used to count the support of each item
    	// c that could potentially extend the rule.
    	// The map associated a set of tids (value) to an item (key).
    	Map<Integer, Set<Integer>> frequentItemsC  = new HashMap<Integer, Set<Integer>>();  
    	
    	// we scan the sequence where I-->J appear to search for items c that we could add.
    	// for each sequence containing I-->J.
    	int left = tidsIJ.size();
    	
    	// For each tid of sequence containing I-->J
    	for(Integer tid : tidsIJ){
    		// get the sequence and get occurences of I in that sequence
    		Sequence sequence = database.getSequences().get(tid);
			Occurence first = occurencesI.get(tid);
			
			// for each itemset after the first occurence of I in that sequence
			int startPos = first.firstItemset+1;
			if(UEIP) {
				if(startPos < matchPosMap.get(tid).get(0)+1) {
					startPos = matchPosMap.get(tid).get(0)+1;
				}
			}
			for(int k = startPos; k < sequence.size(); k++){
				List<Integer> itemset = sequence.get(k);
				// for each item
	itemLoop:	for(int m=0; m< itemset.size(); m++){
					// for each item c in that itemset
					Integer itemC = itemset.get(m);
					
					// We will consider if we could create a rule I --> J U{c}
					// If lexical order is not respected or c is included in the rule already,
					// then we cannot so the algorithm return.
					if(containsLEX(itemsetI, itemC) ||  containsLEXPlus(itemsetJ, itemC)){
						continue;
					}
					
					// UEIP
					if(UEIP && yMatch < YQuery.size() && YQuery.get(yMatch) < itemC) {
						continue;
					}
									
					// countMap
					if(rightCount.get(itemC) < minsuppRelative) {
						continue;
					}
					
					Set<Integer> tidsItemC = frequentItemsC.get(itemC);
					
					// if "c" was seen before but there is not enough sequences left to be scanned
					// to allow IU --> J {c} to reach the minimum support threshold
					if(tidsItemC == null){ 
						if(left < minsuppRelative){
							continue;
						}	
					}else if(tidsItemC.size() + left < minsuppRelative){
						// if "c" was seen before but there is not enough sequences left to be scanned
						// to allow I--> JU{c}  to reach the minimum support threshold,
						// remove "c" and continue the loop of items
						frequentItemsC.remove(itemC);
						continue;
					}
					if(tidsItemC == null){
						// otherwise, if we did not see "c" yet, create a new tidset for "c"
						tidsItemC = new HashSet<Integer>(tidsIJ.size());
						frequentItemsC.put(itemC, tidsItemC);
					}
					// add the current tid to the tidset of "c"
					tidsItemC.add(tid);					
				}
			}
			left--;  // decrease the number of sequences left to be scanned
		}
    	
    	// For each item c found, we create a rule	I ==> JU {c}
    	for(Entry<Integer, Set<Integer>> entry : frequentItemsC.entrySet()){
    		Integer itemC = entry.getKey();
    		// get the tidset of I ==> JU {c}
    		Set<Integer> tidsI_JC = entry.getValue();
    		
    		// if the support of I ==> JU{c} is enough 
    		if(tidsI_JC.size() >= minsuppRelative){  
    			// create the itemset JU{c} and calculate the occurences of JU{c}
    			Set<Integer> tidsJC = new HashSet<Integer>(tidsJ.size());
    			Map<Integer, Occurence> occurencesJC = new HashMap<Integer, Occurence>();
    			
    			// for each sequence containing J
    			for(Integer tid: tidsJ){
    				// Get the first and last occurences of C in that sequence
    				Occurence occurenceC = mapItemCount.get(itemC).get(tid);
    				// if there is an occurence
    	    		if(occurenceC != null){
    	    			// add the tid of the sequence to the tidset of JU{c}
    	    			tidsJC.add(tid);
    	    			// calculate last occurence of JU{c} depending on if
    	    			// the last occurence of J is before the last occurence
    	    			// of c or not.
    	    			Occurence occurenceJ = occurencesJ.get(tid);
    	    			if(occurenceC.lastItemset < occurenceJ.lastItemset){
    	    				occurencesJC.put(tid, occurenceC);
    	    			}else{
    	    				occurencesJC.put(tid, occurenceJ);
    	    			}
    	    		}
    	    	}
    			
    			// Create rule I ==> J U{c} and calculate its confidence   
    	    	// defined as:  sup(I -->J U{c}) /  sup(I)	
    			double confI_JC = ((double)tidsI_JC.size()) / tidsI.size();
				int[] itemsetJC = new int[itemsetJ.length+1];
				System.arraycopy(itemsetJ, 0, itemsetJC, 0, itemsetJ.length);
				itemsetJC[itemsetJ.length]= itemC;

				// UEIP
				int newyMatch = yMatch;
				if(yMatch < YQuery.size() && YQuery.get(yMatch).equals(itemC)) {
					newyMatch++;
				}
				
				// if the confidence is enough
				if(xMatch == XQuery.size() && newyMatch == YQuery.size() && confI_JC >= minConfidence){
					// then it is a valid rule so save it
					saveRule(tidsI_JC, confI_JC, itemsetI, itemsetJC);
					if(DEBUG) {
						Rule newRule = new Rule(itemsetI, itemsetJC, tidsI, tidsJC, tidsI_JC, occurencesI, occurencesJC);
						allRulesFoundForDEBUG.add(newRule);
					}
				}
					
				
				// recursively try to expand the left and right side
				// of the rule
				if(itemsetJC.length < maxConsequentSize) {
					expandRight(itemsetI, itemsetJC, tidsI, tidsJC, tidsI_JC, occurencesI, occurencesJC, xMatch, newyMatch);  // occurencesJ
				}
				if(newyMatch == YQuery.size() && itemsetI.length < maxAntecedentSize) {
					expandLeft(itemsetI, itemsetJC,  tidsI, tidsI_JC, occurencesJC, xMatch);  // occurencesJ
				}
			}
    	}
    	// check the memory usage
    	MemoryLogger.getInstance().checkMemory();
	}

    
	/**
	 * This method use UTP to filter database.
	 * @param database : a sequence database.
	 */
    // gensgen
    private void filterDatabase(SequenceDatabase database){
        
    	int t = 0;
		// for each sequence
		while(t < database.size()){
			
			// get sequence
			Sequence sequence = database.getSequences().get(t);
			
	    	// two set
	        Set<Integer> leftSet = new HashSet<Integer>(XQuery);
	        Set<Integer> rightSet = new HashSet<Integer>(YQuery);
	        
	        // Record the position after matching
	        int leftPos = -1;
	        int rightPos = sequence.size();
	        
	        while(leftPos < sequence.size()-1) {
	        	// if XQuery is matched
	        	if(leftSet.isEmpty()) {
	        		break;
	        	}
	        	List<Integer> itemset = sequence.getItemsets().get(leftPos+1);
				// for each item
				for(int j = 0; j < itemset.size(); j++) {
					// if this item is matched
					if(!leftSet.isEmpty() && leftSet.contains(itemset.get(j))) {
						leftSet.remove(itemset.get(j));
					}
				}
				leftPos++;
	        }
	        
        	if(!leftSet.isEmpty()) {
        		database.remove(t);
        		continue;
        	}
  	
	        // we continue to match YQuery
	        while(rightPos > leftPos && rightPos > 0) {
	        	// if XQuery is matched
	        	if(rightSet.isEmpty()) {
	        		break;
	        	}
	        	List<Integer> itemset = sequence.getItemsets().get(rightPos-1);
				// for each item
				for(int j = 0; j < itemset.size(); j++) {
					// if this item is matched
					if(!rightSet.isEmpty() && rightSet.contains(itemset.get(j))) {
						rightSet.remove(itemset.get(j));
					}
				}
				rightPos--;
	        }
	        
        	if(!rightSet.isEmpty()) {
        		leftPos = rightPos = sequence.size()-1;
        	}
	        
	        ArrayList<Integer> posList = new ArrayList<Integer>();
	        posList.add(leftPos);
	        posList.add(rightPos);
	        matchPosMap.put(t, posList);

    		t++;
		}

    }
    
	/**
	 * This method use UIP to filter database.
	 * @param database : a sequence database.
	 */
	private void filterUnpromisingItem(SequenceDatabase database2) {
		// Count the support of each item in the database in one database pass
		mapItemCount = new HashMap<Integer, Map<Integer, Occurence>>(); // <item, Map<tid, occurence>>
		
		
		// for each sequence
		int k = 0;
		for(Sequence sequence : database.getSequences()){
			int i=0;
			
			// for each itemset
			while(i < sequence.getItemsets().size()){
				List<Integer> itemset = sequence.getItemsets().get(i);
				int j = 0;
				
				// for each item
				while(j < itemset.size()){
					// if the item is not frequent remove it
					Integer item = itemset.get(j);
					if((XQuery.contains(item) && i > matchPosMap.get(k).get(0)) || 
							(YQuery.contains(item) && i < matchPosMap.get(k).get(1))){
						itemset.remove(j);
					}else{
						
						// get the map of occurences of that item
						Map<Integer, Occurence> occurences = mapItemCount.get(item);
						// if this map is null, create a new one
						if(occurences == null){
							occurences = new HashMap<Integer, Occurence>();
							mapItemCount.put(item, occurences);
						}
						// then update the occurence by adding j as the 
						// last occurence in sequence k
						Occurence occurence = occurences.get(k);
						if(occurence == null){
							occurence = new Occurence((short) i, (short) i);
							occurences.put(k, occurence);
						}else{
							occurence.lastItemset = (short) i;
						}				
						
						// otherwise go to next item
						j++;
					}
				}
				if(itemset.size() == 0) {
					if(i < matchPosMap.get(k).get(0)) {
						ArrayList<Integer> posList = matchPosMap.get(k);
						posList.set(0, posList.get(0)-1);
						posList.set(1, posList.get(1)-1);
						matchPosMap.put(k, posList);
					}else if (i < matchPosMap.get(k).get(1)) {
						ArrayList<Integer> posList = matchPosMap.get(k);
						posList.set(1, posList.get(1)-1);
						matchPosMap.put(k, posList);
					}
					// remove this itemset
					sequence.remove(i);
				}else {
					i++;  // go to next itemset
				}
			}
			k++;
		}
	}
    
	/**
	 * This method calculate the frequency of each item in one database pass.
	 * Then it remove all items that are not frequent.
	 * @param database : a sequence database 
	 * @return A map such that key = item
	 *                         value = a map  where a key = tid  and a value = Occurence
	 * This map allows knowing the frequency of each item and their first and last occurence in each sequence.
	 */
	private void removeItemsThatAreNotFrequent(SequenceDatabase database) {
		// remove all items that are not frequent from the database
		int k = 0;
		// for each sequence
		for(Sequence sequence : database.getSequences()){
			int i=0;
			
			// for each itemset
			while(i < sequence.getItemsets().size()){
				List<Integer> itemset = sequence.getItemsets().get(i);
				int j=0;
				
				// for each item
				while(j < itemset.size()){
					// if the item is not frequent remove it
					if(mapItemCount.get(itemset.get(j)).size() < minsuppRelative || 
							(leftCount.get(itemset.get(j)) < minsuppRelative && rightCount.get(itemset.get(j)) < minsuppRelative)){
						itemset.remove(j);
					}else{
						if(leftCount.get(itemset.get(j)) < minsuppRelative && i <= matchPosMap.get(k).get(0)) {
							itemset.remove(j);
						}else if(rightCount.get(itemset.get(j)) < minsuppRelative && i >= matchPosMap.get(k).get(1)) {
							itemset.remove(j);
						}
						// otherwise go to next item
						j++;
					}
				}
				i++;  // go to next itemset
			}
			k++;
		}
		// return the map of occurences of items
		// return mapItemCount;
	}
	
	
	private void printArray(int[] itemset) {
		for(int i = 0; i < itemset.length; i++) {
			System.out.print(itemset[i] + " ");
		}
	}

	/**

	 * This method checks if the item "item" is in the itemset.
	 * It asumes that items in the itemset are sorted in lexical order
	 * This version also checks that if the item "item" was added it would be the largest one
	 * according to the lexical order.
	 * @param itemset an itemset
	 * @param item  the item
	 * @return return true if the above conditions are met, otherwise false
	 */
	boolean containsLEXPlus(int[] itemset, int item) {
		// for each item in itemset
		for(int i=0; i< itemset.length; i++){
			// check if the current item is equal to the one that is searched
			if(itemset[i] == item){
				// if yes return true
				return true;
			// if the current item is larger than the item that is searched,
			// then return true because if if the item "item" was added it would be the largest one
			// according to the lexical order.  
			}else if(itemset[i] > item){
				return true; // <-- XXXX
			}
		}
		// if the searched item was not found, return false.
		return false;
	}
	
	/**
	 * This method checks if the item "item" is in the itemset.
	 * It assumes that items in the itemset are sorted in lexical order
	 * @param itemset an itemset
	 * @param item  the item
	 * @return return true if the item
	 */
	boolean containsLEX(int[] itemset, int item) {
		// for each item in itemset
		for(int i=0; i< itemset.length; i++){
			// check if the current item is equal to the one that is searched
			if(itemset[i] == item){
				// if yes return true
				return true;
			// if the current item is larger than the item that is searched,
			// then return false because of the lexical order.
			}else if(itemset[i] > item){
				return false;  // <-- xxxx
			}
		}
		// if the searched item was not found, return false.
		return false;
	}

	/**
	 * Set the number of items that a rule antecedent should contain (optional).
	 * @param maxAntecedentSize the maximum number of items
	 */
	public void setMaxAntecedentSize(int maxAntecedentSize) {
		this.maxAntecedentSize = maxAntecedentSize;
	}


	/**
	 * Set the number of items that a rule consequent should contain (optional).
	 * @param maxConsequentSize the maximum number of items
	 */
	public void setMaxConsequentSize(int maxConsequentSize) {
		this.maxConsequentSize = maxConsequentSize;
	}
	
	/**
	 * Print statistics about the last algorithm execution to System.out.
	 */
	public void printStats() {
		System.out.println("===============  TaSRM - STATS ==========");
		System.out.println("Sequential rules count: " + ruleCount);
		System.out.println("Target sequential rules count: " + validCount);
		System.out.println("Expand count: " + expandCount);
		System.out.println("Total time: " + (double)(timeEnd - timeStart)/1000 + " s");
		System.out.println("Max memory: " + MemoryLogger.getInstance().getMaxMemory() + " mb");
		System.out.println("==========================================");
	}

}
