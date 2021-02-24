#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void my_func(void);

unsigned long ctr = 0;
void my_func(void) {
  ctr++;
  //if (ctr % 0x1000000 == 0)
    printf("Func called 0x%lx times\n", ctr);
}

int first = 0;
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  // Called whenever a block is translated
  printf("Instrumenting block at: 0x%lx\n", qemu_plugin_tb_vaddr(tb));
  insert_call(my_func, 1);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
