#include <stdio.h>
#include <stdint.h>
#include <interpose.h>

int fake_puts(const char *s) {
    printf("whee %s\n", s);
    return 0;
}

__attribute__((constructor))
static void hello() {
    fprintf(stderr, "Someone loaded me\n");
    union {
        char bytes[4];
        uint32_t num;
    } u;
    u.bytes[0] = 0x12;
    u.bytes[1] = 0x34;
    u.bytes[2] = 0x56;
    u.bytes[3] = 0x78;
    fprintf(stderr, "le->78563412 be->12345678 actual=%x\n", u.num);
    fprintf(stderr, "%d\n", interpose("_puts", fake_puts)); 
}
