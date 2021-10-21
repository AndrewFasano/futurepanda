#include <stdio.h>
#include <qemu-plugin.h>
#include <panda-plugin.h>

#include "ppp_srv.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void my_on_exit(int x, bool b);

void my_on_exit(int x, bool b) {
  printf("client on_exit runs with args: %d, %d\n", x, b);
}


QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

    // TODO: register a PPP function with ppp_srv
    PPP_REG_CB("ppp_srv", on_exit, my_on_exit)
    printf("Client registered on_exit callback\n");
    return 0;
}
