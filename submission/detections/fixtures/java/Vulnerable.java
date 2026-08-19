/*
 * Positive fixture (intra-procedural).
 *
 * CWE-88 embedded sub-option injection: an externally controlled value is
 * concatenated into ONE delimiter-structured option-argument (comma-separated
 * key=value grammar) and passed to a process launcher through an argument
 * array. No shell is involved and the OS-level argument count does not change,
 * but the receiving command reparses the value and an attacker-controlled
 * delimiter can create an additional logical option.
 *
 * The construction and the launch are in the same method, so the
 * intra-procedural rule flags it.
 */
public class Vulnerable {

    public void handle(String target, String externalValue) throws Exception {
        // The untrusted field is embedded into a comma/equals option template
        // without neutralizing the sub-option delimiter.
        String opt = "endpoint=trusted.example,id=" + externalValue;
        new ProcessBuilder(target, "-o", opt).start();
    }
}
