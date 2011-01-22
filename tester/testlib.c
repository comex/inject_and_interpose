#include <stdio.h>

__attribute__((constructor))
static void hello() {
    fprintf(stderr, "Someone loaded me\n");
}
