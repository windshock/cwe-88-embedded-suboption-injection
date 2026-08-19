#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Product-independent CWE-88 demonstrator.
 *
 * This program intentionally models a command that accepts one OS-level
 * option-argument whose contents are a comma-delimited sub-option language:
 *
 *     demo_target -o "endpoint=trusted.example,id=42"
 *
 * The important boundary is that argv[2] remains ONE OS-level argument while
 * getsubopt() parses multiple logical options from its contents.
 *
 * No network access, shell execution, file modification, or vendor code is
 * involved. The program only prints the resulting parser state.
 */

enum option_index {
    OPT_ENDPOINT = 0,
    OPT_ID,
    OPT_LOG_TARGET
};

static char *const tokens[] = {
    [OPT_ENDPOINT] = "endpoint",
    [OPT_ID] = "id",
    [OPT_LOG_TARGET] = "log_target",
    NULL
};

struct config {
    char endpoint[128];
    char id[128];
    char log_target[128];
    unsigned endpoint_occurrences;
    unsigned parsed_options;
};

static void assign_value(char *dst, size_t dst_size, const char *value)
{
    if (value == NULL) {
        value = "";
    }
    (void)snprintf(dst, dst_size, "%s", value);
}

int main(int argc, char **argv)
{
    struct config cfg;
    char *work = NULL;
    char *cursor = NULL;
    char *value = NULL;
    int opt;

    memset(&cfg, 0, sizeof(cfg));
    assign_value(cfg.endpoint, sizeof(cfg.endpoint), "unset");
    assign_value(cfg.id, sizeof(cfg.id), "unset");
    assign_value(cfg.log_target, sizeof(cfg.log_target), "unset");

    printf("[target] argc=%d\n", argc);
    for (int i = 0; i < argc; ++i) {
        printf("[target] argv[%d]=<%s>\n", i, argv[i]);
    }

    if (argc != 3 || strcmp(argv[1], "-o") != 0) {
        fprintf(stderr, "usage: %s -o key=value,key=value\n", argv[0]);
        return 2;
    }

    work = strdup(argv[2]);
    if (work == NULL) {
        perror("strdup");
        return 2;
    }

    cursor = work;
    while (*cursor != '\0') {
        opt = getsubopt(&cursor, tokens, &value);
        cfg.parsed_options++;

        switch (opt) {
        case OPT_ENDPOINT:
            cfg.endpoint_occurrences++;
            /*
             * Repeated assignment intentionally models a common parser state
             * update. If endpoint appears twice, the later occurrence becomes
             * the final value. That "last assignment wins" behavior is a
             * property of THIS demo logic, not of getsubopt() itself.
             */
            assign_value(cfg.endpoint, sizeof(cfg.endpoint), value);
            printf("[parse] endpoint=%s\n", value ? value : "");
            break;

        case OPT_ID:
            assign_value(cfg.id, sizeof(cfg.id), value);
            printf("[parse] id=%s\n", value ? value : "");
            break;

        case OPT_LOG_TARGET:
            assign_value(cfg.log_target, sizeof(cfg.log_target), value);
            printf("[parse] log_target=%s\n", value ? value : "");
            break;

        default:
            printf("[parse] unknown=%s\n", value ? value : "");
            break;
        }
    }

    printf("[result] parsed_options=%u\n", cfg.parsed_options);
    printf("[result] endpoint_occurrences=%u\n", cfg.endpoint_occurrences);
    printf("[result] endpoint=%s\n", cfg.endpoint);
    printf("[result] id=%s\n", cfg.id);
    printf("[result] log_target=%s\n", cfg.log_target);

    free(work);
    return 0;
}
