#include <stdio.h>
#include <qemu-plugin.h>
#include <panda-plugin.h>

#include "ppp_srv.h"
#define PLUGIN_MAIN // Define after external includes (if we had include ppp_client.h put it next) N

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void my_on_exit(int x, bool b);

void my_on_exit(int x, bool b) {
  printf("Client: on_exit runs with args: %d, %d\n", x, b);

  printf("Client: calls ppp_srv's do_add(1): %d\n", ppp_srv_do_add(1));
  printf("Client: calls ppp_srv's do_sub(1): %d\n", ppp_srv_do_sub(1));
}


QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

    // register our my_on_exit function to run on the on_exit PPP-callback
    // exported by ppp_srv
    PPP_REG_CB("ppp_srv", on_exit, my_on_exit)
    printf("Client: calling ppp_srv's do_add(0) to get %d\n", ppp_srv_do_add(0));
    printf("Client: registered on_exit callback\n");
    return 0;
}
