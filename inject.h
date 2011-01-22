#include <unistd.h>
#include <mach/kern_return.h>

// asynchronous
kern_return_t inject(pid_t pid, const char *path, const char **failure_string);
