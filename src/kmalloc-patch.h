#ifndef KMALLOC_PATCH
#define KMALLOC_PATCH
#include <kvm.h>

/**
 * Output of "llvm-objdump -dr kmalloc.ko"
 
0000000000000040 <kmalloc>:
      40: 55                            pushq   %rbp
      41: 48 89 e5                      movq    %rsp, %rbp
      44: 53                            pushq   %rbx
      45: 50                            pushq   %rax
      46: 48 89 f3                      movq    %rsi, %rbx
      49: 48 8b 3e                      movq    (%rsi), %rdi
      4c: 48 c7 c6 00 00 00 00          movq    $0, %rsi
                000000000000004f:  R_X86_64_32S M_TEMP
      53: ba 01 00 00 00                movl    $1, %edx
      58: e8 00 00 00 00                callq   0x5d <kmalloc+0x1d>
                0000000000000059:  R_X86_64_PLT32       malloc-0x4
      5d: 48 89 45 f0                   movq    %rax, -16(%rbp)
      61: 48 8b 73 08                   movq    8(%rbx), %rsi
      65: 48 8d 7d f0                   leaq    -16(%rbp), %rdi
      69: ba 08 00 00 00                movl    $8, %edx
      6e: e8 00 00 00 00                callq   0x73 <kmalloc+0x33>
                000000000000006f:  R_X86_64_PLT32       copyout-0x4
      73: 48 83 c4 08                   addq    $8, %rsp
      77: 5b                            popq    %rbx
      78: 5d                            popq    %rbp
      79: c3                            retq
 */

/* Kernel memory allocation (kmalloc) function code. */

static unsigned char kmalloc[] =
   "\x55"                           // pushq %rbp
   "\x48\x89\xe5"                   // movq  %rsp, %rbp
   "\x53"                           // pushq %rbx
   "\x50"                           // pushq %rax
   "\x48\x89\xf3"                   // movq  %rsi, %rbx
   "\x48\x8b\x3e"                   // movq  (%rsi), %rdi
   "\x48\xc7\xc6\x00\x00\x00\x00"   // movq $0 < M_TEMP >, %rsi
   "\xba\x01\x00\x00\x00"           // movl $1, %edx
   "\xe8\x00\x00\x00\x00"           // callq < malloc >
   "\x48\x89\x45\xf0"               // movq %rax, -16(%rbp)
   "\x48\x8b\x73\x08"               // movq 8(%rbx), %rsi
   "\x48\x8d\x7d\xf0"               // leaq -16(%rbp), %rdi
   "\xba\x08\x00\x00\x00"           // movl $8, %edx
   "\xe8\x00\x00\x00\x00"           // callq < copyout >
   "\x48\x83\xc4\x08"               // addq $8, %rsp
   "\x5b"                           // popq %rbx
   "\x5d"                           // popq %rbp
   "\xc3";                          // retq

/*
 * The relative address of the instructions following the call statements
 * within kmalloc.
 */

#define MALLOC_RET_OFFSET 0x1d
#define COPYOUT_RET_OFFSET 0x33

unsigned long kmalloc_patch(kvm_t *kd, size_t size);
#endif
