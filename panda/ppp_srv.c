#include <stdio.h>
#include <qemu-plugin.h>
#include <panda-plugin.h>
#include <gmodule.h>

#define PLUGIN_MAIN  // Define after external includes, before we include ppp_srv.h
#include "ppp_srv.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

PPP_PROT_REG_CB(on_exit);
PPP_CB_BOILERPLATE(on_exit);

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
  printf("ppp_srv exit triggered, running all registered PPP callbacks\n");
  PPP_RUN_CB(on_exit, 0, true);

}

QEMU_PLUGIN_EXPORT int do_add(int x) {
  return x+1;
}

QEMU_PLUGIN_EXPORT int do_sub(int x) {
  return x-1;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
