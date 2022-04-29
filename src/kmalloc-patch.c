#include "kmalloc-patch.h"
#include <fcntl.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <unistd.h>

/*
 * Indices of call addresses within the kmalloc buffer.
 */
#define MTEMP_INDEX 15
#define MALLOC_CALL_INDEX 25
#define COPYOUT_CALL_INDEX 47

unsigned long kmalloc_patch(kvm_t *kd, size_t size)
{
   int i;
   char errbuf[_POSIX2_LINE_MAX];
   struct nlist nl[] = {{NULL}, {NULL}, {NULL}, {NULL}, {NULL},};
   size_t kmalloc_size = sizeof(kmalloc);
   unsigned char syscall_code[kmalloc_size];
   unsigned long addr;

   // syscall to overwrite (fchownat)
   int syscall_num = SYS_fchownat;
   char * sym_syscall = "sys_fchownat";

   // M_TEMP 
   char * sym_M_TEMP = "M_TEMP";

   // malloc 
   char * sym_malloc = "malloc";

   // copyout
   char * sym_copyout = "copyout";

   nl[0].n_name = sym_syscall;
   nl[1].n_name = sym_M_TEMP;
   nl[2].n_name = sym_malloc;
   nl[3].n_name = sym_copyout;

   /* Find the address of syscall to overwrite, M_TEMP, malloc, and copyout. */

   if (kvm_nlist(kd, nl) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      return 0;
   }

   printf("[-] %s address is 0x%lx\n", sym_syscall, nl[0].n_value);
   printf("[-] %s address is 0x%lx\n", sym_M_TEMP, nl[1].n_value);
   printf("[-] %s address is 0x%lx\n", sym_malloc, nl[2].n_value);
   printf("[-] %s address is 0x%lx\n", sym_copyout, nl[3].n_value);

   for (i = 0; i < 4; i++) {
      if (!nl[i].n_value) {
	 fprintf(stderr, "[x] ERROR: Symbol %s not found\n",
		 nl[i].n_name);
	 return 0;
      }
   }

   /*
    * Patch the kmalloc function code to contain the correct addresses for
    * M_TEMP, malloc, and copyout.
    */

   *(u_int32_t *)&kmalloc[MTEMP_INDEX] = nl[1].n_value;
   *(u_int32_t *)&kmalloc[MALLOC_CALL_INDEX] = nl[2].n_value -
      (nl[0].n_value + MALLOC_RET_OFFSET);
   *(u_int32_t *)&kmalloc[COPYOUT_CALL_INDEX] = nl[3].n_value -
      (nl[0].n_value + COPYOUT_RET_OFFSET);

   /* Save sizeof(kmalloc) bytes of syscall to overwrite. */

   printf("[-] Reading %lu bytes of %s\n", kmalloc_size, sym_syscall);

   ssize_t bytes_read=-1;

   if ((bytes_read=kvm_read(kd, nl[0].n_value, syscall_code,
				   kmalloc_size)) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      return 0;
   } else {
      printf("[-] Read %lu bytes\n", bytes_read);

      for (int i = 0; i < bytes_read; i++) {
         printf("\\x%02hhx ", (unsigned char)syscall_code[i]);
      }

      printf("\n");
   }

   /* Overwrite sym_syscall with kmalloc. */

   printf("[-] Overwriting %s with kmalloc\n", sym_syscall);

   if (kvm_write(kd, nl[0].n_value, kmalloc, sizeof(kmalloc)) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      return 0;
   }

   /* Allocate kernel memory. */

   printf("[-] Making overwritten syscall to allocate %zu bytes of kernel memory\n", size);

   if (syscall(syscall_num, size, &addr) != 0) {
      perror("[x] Failed to allocate kernel memory with syscall");
   }

   /* Restore syscall. */

   printf("[-] Restoring %s\n", sym_syscall);

   if (kvm_write(kd, nl[0].n_value, syscall_code, kmalloc_size) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      return 0;
   }

   return addr;
}
