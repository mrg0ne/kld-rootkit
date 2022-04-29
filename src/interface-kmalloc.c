#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <kvm.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <strings.h>

int main(int argc, char *argv[]) {
   int syscall_num, modid;
   struct module_stat stat;
   unsigned long addr, nbytes, bytes_left;
   kvm_t *kd;
   char errbuf[_POSIX2_LINE_MAX];
   unsigned char *buf, *ptr;
   unsigned char stamp[] = "\xef\xbe\xad\xde";

   if (argc != 2) {
      printf("Usage:\n%s <size>\n", argv[0]);
      exit(0);
   }

   nbytes = atol(argv[1]);

   stat.version = sizeof(stat);
   modid = modfind("sys/kmalloc");

   if (modid < 0) {
      perror("[x] modfind sys/kmalloc failed");
      exit(-1);
   }

   if (modstat(modid, &stat) < 0) {
      perror("[x] modstat failed");
      exit(-1);
   }

   syscall_num = stat.data.intval;
   syscall(syscall_num, nbytes, &addr);
   printf("Allocated %lu bytes of kernel memory\n", nbytes);
   printf("Address of allocated kernel memory: 0x%lx\n", addr);

   /* Initialize kernel virtual memory access. */
   kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

   if (kd == NULL) {
      fprintf(stderr, "ERROR: %s\n", errbuf);
      exit(-1);
   }

   buf = malloc(nbytes);
   ptr = buf;
   bytes_left = nbytes;

   while (bytes_left > 0) {
      if (bytes_left >= 4) {
         bcopy(stamp, ptr, 4);
         bytes_left-=4;
	 ptr+=4;
      } else {
         bcopy(stamp, ptr, bytes_left);
	 bytes_left=0;
      }
   }

   if (kvm_write(kd, addr, buf, nbytes) < 0) {
      printf("[x] kvm_write of %lu bytes at 0x%lx failed\n", nbytes, addr);
      perror("");
   } else {
      printf("[-] Successfully wrote %lu bytes at 0x%lx\n", nbytes, addr);
   }

   free(buf);
   exit(0);
}
