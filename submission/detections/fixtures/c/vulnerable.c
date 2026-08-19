/*
 * Positive fixture (intra-procedural).
 *
 * CWE-88 embedded sub-option injection: an externally controlled field is
 * formatted into ONE delimiter-structured option-argument (a comma-separated
 * key=value option grammar) and passed to a non-shell process launcher through
 * an argument vector. No shell is involved and the OS-level argument count does
 * not change, but the receiving command reparses the value and an
 * attacker-controlled delimiter can create an additional logical option.
 *
 * The construction (snprintf building the "endpoint=trusted.example,id=%s"
 * template) and the launch (execvp with the buffer in argv) are in the same
 * function, so the intra-procedural rule flags it.
 *
 * Self-contained: libc/exec prototypes are declared locally so the CodeQL
 * cpp extractor (--build-mode=none) is complete without any compiler/build.
 */

typedef unsigned long size_t;

int snprintf(char *str, size_t size, const char *format, ...);
int execvp(const char *file, char *const argv[]);

static void handle(const char *target, const char *external_value) {
    char opt[256];

    /* The untrusted field is embedded into a comma/equals option template
     * without neutralizing the sub-option delimiter. */
    snprintf(opt, sizeof opt, "endpoint=trusted.example,id=%s", external_value);

    char *argv[] = {(char *)target, "-o", opt, (char *)0};
    execvp(target, argv);
}
