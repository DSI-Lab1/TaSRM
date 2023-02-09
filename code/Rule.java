import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/**
 * This class represents a sequential rule.
 */
public class Rule {
	
	int[] itemsetI;
	int[] itemsetJ; 
	Set<Integer> tidsI;
	Set<Integer> tidsJ;
	Set<Integer> tidsIJ;
	Map<Integer, Occurence> occurencesI;
	Map<Integer, Occurence> occurencesJ;

	public Rule(int[] itemsetI, int[] itemsetJ, Set<Integer> tidsI,
			Set<Integer> tidsJ, Set<Integer> tidsIJ,
			Map<Integer, Occurence> occurencesI,
			Map<Integer, Occurence> occurencesJ) {
			this.itemsetI = itemsetI;
			this.itemsetJ = itemsetJ;
			this.tidsI = tidsI;
			this.tidsJ = tidsJ;
			this.tidsIJ = tidsIJ;
			this.occurencesI = occurencesI;
			this.occurencesJ = occurencesJ;
	}
	
	@Override
	public String toString() {
		return Arrays.toString(itemsetI) + " ==> " + Arrays.toString(itemsetJ);
	}

}
