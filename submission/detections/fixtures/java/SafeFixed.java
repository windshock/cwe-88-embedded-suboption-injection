/*
 * Negative fixture.
 *
 * The untrusted field is represented as its own independent argument with no
 * embedded delimiter grammar, so it cannot be reinterpreted as a sibling
 * option. There is no comma/equals option template built from external data,
 * so neither the intra-procedural nor the interprocedural rule should flag it.
 */
public class SafeFixed {

    public void handle(String target, String externalValue) throws Exception {
        // Each logical field is passed as a separate argument. The receiving
        // command never reparses a delimiter-structured value built from
        // untrusted input.
        new ProcessBuilder(target, "--endpoint", "trusted.example", "--id", externalValue).start();
    }
}
