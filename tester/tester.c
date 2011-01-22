#include <inject.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    const char *fs;
    printf("kr=%d  ", (int) inject(atoi(argv[1]), argv[2], &fs));
    printf("%s\n", fs);
    return 0;
}
