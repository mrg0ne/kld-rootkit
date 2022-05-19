#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <stdlib.h>
#include <unistd.h>
#include "shadow_sysent.h"

int main(int argc, char **argv) {

   int syscall_num = 0;
   u_int16_t lport, fport = 0;

   if (argc < 4) {
      printf("Usage: %s <syscall number> <local port> <foreign port>\n",
         argv[0]);
      return -1;
   } else {
      syscall_num = atoi(argv[1]);
      lport = atoi(argv[2]);
      fport = atoi(argv[3]);
   }

   if (syscall(syscall_num, lport, fport) != 0) {
      printf("[x] whisper syscall %d failed. Is module loaded?\n", syscall_num);
      return -2;
   }

   return 0;
}
