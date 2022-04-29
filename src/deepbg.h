#ifndef _DEEPBG_H_
#define _DEEPBG_H_
#include <sys/proc.h>

struct deepbg_args {
   pid_t p_pid;   // process ID
};

/* System call to hide a running process. */
static int deepbg(struct thread *td, void *syscall_args);
#endif
