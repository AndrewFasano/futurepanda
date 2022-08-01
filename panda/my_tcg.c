#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <qemu-plugin.h>
#include <glib.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void my_func(void);

unsigned long ctr = 0;
void my_func(void) {
  ctr++;
  g_autoptr(GString) report = g_string_new("Functrion called ");
  g_string_append_printf(report, "0x%lx times\n", ctr);
  qemu_plugin_outs(report->str);
  g_string_free(report, true);
}

int first = 0;
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  // Called whenever a block is translated
  g_autoptr(GString) report = g_string_new("Instrumenting block at ");
  g_string_append_printf(report, "0x%lx\n", qemu_plugin_tb_vaddr(tb));
  qemu_plugin_outs(report->str);
  g_string_free(report, true);

  insert_call(my_func, 1);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
