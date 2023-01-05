#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "coverage";
#include <plugin-qpp.h>

static FILE *fp;
static const char *file_name = "file.trace";
static GMutex lock;

typedef struct {
    uint32_t start;
    uint64_t hash;
    bool     exec;
} bb_entry_t;

//static OsiProc *current_procs[8] = {0}; // XXX max number of CPUS?

/* Translated blocks */
static GPtrArray *blocks;

const uint64_t fnv_prime = 0x100000001b3ULL;

static void printf_el(gpointer data, gpointer user_data)
{
    bb_entry_t *bb = (bb_entry_t *)data;
    if (bb->exec) {
        fprintf(fp, "%lx\n", bb->hash);
    }
    g_free(bb);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_mutex_lock(&lock);
    g_ptr_array_foreach(blocks, printf_el, NULL);

    /* Clear */
    g_ptr_array_free(blocks, true);

    fclose(fp);
    g_mutex_unlock(&lock);
}

static void plugin_init(void)
{
    fp = fopen(file_name, "wb");
    blocks = g_ptr_array_sized_new(128);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    if (qemu_plugin_in_privileged_mode()) 
      return;

    bb_entry_t *bb = (bb_entry_t *) udata;
    g_mutex_lock(&lock);
    bb->exec = true;
    g_mutex_unlock(&lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n = qemu_plugin_tb_n_insns(tb);
    // fnv hashing: https://www.programmingalgorithms.com/algorithm/fnv-hash/c/
    // and https://github.com/haipome/fnv/blob/master/fnv.c
    uint64_t hash = 0;

    g_mutex_lock(&lock);
    bb_entry_t *bb = g_new0(bb_entry_t, 1);
    for (int i = 0; i < n; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        hash *= fnv_prime;

        // Get raw bytes in a large container
        uint64_t insn_bytes  = *(uint64_t*)qemu_plugin_insn_data(insn);
        size_t insn_size = qemu_plugin_insn_size(insn);
        //bb->size += insn_size

        // If I were good at math there'd be a cleaner way. Compiler should optimize?
        for (int i=64/8; i >= insn_size; i--) {
          ((char*)&insn_bytes)[i] = 0;
        }
        hash ^= insn_bytes;
    }

    bb->start = pc;
    bb->hash = hash;
    bb->exec = false;
    g_ptr_array_add(blocks, bb);

    g_mutex_unlock(&lock);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)bb);

}

#if 0
void task_change(gpointer evdata, gpointer udata);
void task_change(gpointer evdata, gpointer udata) {
  OsiProc *p = get_current_process_qpp();
  unsigned int cpu_index = *(unsigned int*)evdata;

  if (current_procs[cpu_index] != NULL) {
    // Had old state on this CPU - free it
    free(current_procs[cpu_index]);
  }

  if (p == NULL) {
    // Unknown state now?
    current_procs[cpu_index] = NULL;
  } else {
    // Have state to save
    current_procs[cpu_index] = (OsiProc*)malloc(sizeof(OsiProc));
    memcpy(current_procs[cpu_index], p, sizeof(OsiProc));
  }
}
#endif

void vcpu_hypercall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t a1, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
  // Debug only
  if (num == 0) {
    char comm[16];
    printf("Plugin sees hypercall. Num=%ld: Guest kernel is switching to process with name at %lx =>", num, a1);
    if (qemu_plugin_read_guest_virt_mem(a1, &comm, sizeof(comm)) != -1) {
      printf("'%s'\n", comm);
    } else {
      printf("[error]\n");
    }
  }else {
    printf("Num %ld arg1 %ld\n", num, a1);
  }

}


QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        g_autofree char **tokens = g_strsplit(argv[i], "=", 2);
        if (g_strcmp0(tokens[0], "filename") == 0) {
            file_name = g_strdup(tokens[1]);
        }
    }

    plugin_init();

    //qemu_plugin_reg_callback("osi", "on_task_change", task_change);
    //qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_hypercall_cb(id, vcpu_hypercall);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
