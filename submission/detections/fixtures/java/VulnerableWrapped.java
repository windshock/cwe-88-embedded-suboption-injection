/*
 * Positive fixture (interprocedural).
 *
 * Same CWE-88 embedded sub-option injection shape as Vulnerable.java, but the
 * constructed option-argument is handed to a small launch wrapper that many
 * callers would share. The construction and the process launch are in
 * different methods, so only the interprocedural (taint-tracking) rule flags
 * it; the intra-procedural rule misses it.
 */
public class VulnerableWrapped {

    public void handle(String target, String externalValue) throws Exception {
        String opt = "endpoint=trusted.example,id=" + externalValue;
        launch(target, opt);
    }

    private void launch(String target, String opt) throws Exception {
        new ProcessBuilder(target, "-o", opt).start();
    }
}
