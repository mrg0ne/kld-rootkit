#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/proc.h>
#include "shadow_sysent.h"

int main(int argc, char **argv) {

   int syscall_num = 0;
   pid_t pid = 0;

   if (argc < 3) {
      printf("Usage: %s <syscall number> <pid>\n",
         argv[0]);
      return -1;
   } else {
      syscall_num = atoi(argv[1]);
      pid = atoi(argv[2]);
   }

   if (syscall(syscall_num, pid) != 0) {
      printf("[x] deepbg syscall %d failed. Is module loaded?\n", syscall_num);
      return -2;
   }

   return 0;
}
