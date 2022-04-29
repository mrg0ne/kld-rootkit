#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {

   if (argc < 4) {
      printf("Usage: %s <syscall num> <lport> <fport>\n", argv[0]);
      return -1;
   }

   if (syscall(atoi(argv[1]), atoi(argv[2]), atoi(argv[3])) != 0) {
      perror("[x] whisper syscall %d failed. Is module loaded?");
      return -1;
   }

   return 0;
}
