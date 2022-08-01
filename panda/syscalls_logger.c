#include <stdio.h>
#include <qemu-plugin.h>
#include <panda-plugin.h>
#include <glib.h>
#include "syscalls3.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void log_syscall(uint64_t pc, uint64_t callno);

void log_syscall(uint64_t pc, uint64_t callno) {
    g_autoptr(GString) report = g_string_new("Syscall at ");
    g_string_append_printf(report, "Syscall at %lx: %ld\n", pc, callno);
    qemu_plugin_outs(report->str);
    g_string_free(report, true);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

    PPP_REG_CB("syscalls3", on_all_sys_enter, log_syscall)
    return 0;
}
