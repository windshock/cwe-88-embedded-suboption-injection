/*
 * Positive fixture (interprocedural).
 *
 * Same CWE-88 embedded sub-option injection shape as vulnerable.c, but the
 * constructed option-argument is handed to a small launch wrapper that many
 * callers would share. The snprintf construction and the exec* launch live in
 * DIFFERENT functions, so only the interprocedural (taint-tracking) rule flags
 * it; the intra-procedural rule misses it.
 *
 * Self-contained: libc/exec prototypes are declared locally so the CodeQL
 * cpp extractor (--build-mode=none) is complete without any compiler/build.
 */

typedef unsigned long size_t;

int snprintf(char *str, size_t size, const char *format, ...);
int execvp(const char *file, char *const argv[]);

/* The launch wrapper: performs the exec* with the caller-built option in argv.
 * The buffer crosses the function boundary through the `opt` parameter. */
static void launch(const char *target, char *opt) {
    char *argv[] = {(char *)target, "-o", opt, (char *)0};
    execvp(target, argv);
}

static void handle(const char *target, const char *external_value) {
    char opt[256];

    snprintf(opt, sizeof opt, "endpoint=trusted.example,id=%s", external_value);

    launch(target, opt);
}
