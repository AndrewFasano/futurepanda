#include <stdio.h>
#include <qemu-plugin.h>
#include <plugin-qpp.h>
#include <gmodule.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "osi";
#include "osi.h"

static qemu_plugin_id_t self_id;
QEMU_PLUGIN_EXPORT OsiProc *get_current_process(void) {
    OsiProc *p = NULL;
    qemu_plugin_run_callback(self_id, "on_get_current_process", &p, NULL);
    return p;
}

QEMU_PLUGIN_EXPORT void notify_task_change(unsigned int cpu_index, void* udata) {
    qemu_plugin_run_callback(self_id, "on_task_change", &cpu_index, NULL);
}

QEMU_PLUGIN_EXPORT OsiProc *get_process(const OsiProcHandle *h) {
    OsiProc *p = NULL; // output
    struct get_process_data* evdata = (struct get_process_data*)malloc(sizeof(struct get_process_data));
    evdata->h = h;
    evdata->p = &p;

    qemu_plugin_run_callback(self_id, "on_get_process", evdata, NULL);
    return p;
}

QEMU_PLUGIN_EXPORT OsiProcHandle *get_current_process_handle(void) {
    OsiProcHandle *h = NULL;
    qemu_plugin_run_callback(self_id, "on_get_current_process_handle", &h, NULL);
    return h;
}

QEMU_PLUGIN_EXPORT GArray *get_mappings(OsiProc *p) {
    GArray *m = NULL; // output
    struct get_mappings_data* evdata = (struct get_mappings_data*)malloc(sizeof(struct get_mappings_data));
    evdata->out = &m;
    evdata->p = p;

    qemu_plugin_run_callback(self_id, "on_get_mappings", evdata, NULL);
    return m;
}


QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {
    self_id = id;
    qemu_plugin_outs("osi_stub loaded\n");
    qemu_plugin_create_callback(id, "on_get_current_process");
    qemu_plugin_create_callback(id, "on_get_process");
    qemu_plugin_create_callback(id, "on_get_current_process_handle");
    qemu_plugin_create_callback(id, "on_get_mappings");
    qemu_plugin_create_callback(id, "on_task_change");
    return 0;
}
