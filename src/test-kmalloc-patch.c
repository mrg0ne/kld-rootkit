#include "kmalloc-patch.h"
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>

int main(int argc, char **argv) {
   unsigned long num_bytes = 0;
   unsigned long buf = 0;
   char errbuf[_POSIX2_LINE_MAX];

   if (argc < 2) {
      printf("usage: %s <num bytes to allocate>\n", argv[0]);
      return -1;
   }

   num_bytes = atol(argv[1]);
   kvm_t *kd;

   /* Initialize kernel virtual memory access. */
   kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

   if (kd == NULL) {
      fprintf(stderr, "ERROR: %s\n", errbuf);
      exit(-1);
   }

   buf = kmalloc_patch(kd, num_bytes);

   if (buf != 0) {
      printf("Allocated %lu bytes at 0x%lx\n", num_bytes, buf);
   } else {
      printf("Failed to allocate %lu bytes\n", num_bytes);
   }

   /* Close kd. */
   if (kvm_close(kd) < 0) {
      fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
      exit(-1);
   }

}
