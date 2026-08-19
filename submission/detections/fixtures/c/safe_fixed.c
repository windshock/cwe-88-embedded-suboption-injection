/*
 * Negative fixture.
 *
 * The untrusted field is represented as its own independent argv entry with no
 * embedded delimiter grammar, so it cannot be reinterpreted as a sibling
 * option. There is no comma/equals option template built from external data, so
 * neither the intra-procedural nor the interprocedural rule should flag it.
 *
 * Self-contained: libc/exec prototypes are declared locally so the CodeQL
 * cpp extractor (--build-mode=none) is complete without any compiler/build.
 */

typedef unsigned long size_t;

int execvp(const char *file, char *const argv[]);

static void handle(const char *target, const char *external_value) {
    /* Each logical field is passed as a separate argument. The receiving
     * command never reparses a delimiter-structured value built from untrusted
     * input. */
    char *argv[] = {
        (char *)target,
        "--endpoint", "trusted.example",
        "--id", (char *)external_value,
        (char *)0
    };
    execvp(target, argv);
}
