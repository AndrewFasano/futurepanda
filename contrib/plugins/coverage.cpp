#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <vector>

extern "C" {
#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "coverage";
#include <plugin-qpp.h>
}

static FILE *fp;
static const char *file_name = "file.trace";
static GMutex lock;

typedef struct {
    uint32_t start;
    //uint64_t hash;
    char mod[64]; // TODO use an ID?
    uint32_t offset;
    bool     exec;
} bb_entry_t;

//static OsiProc *current_procs[8] = {0}; // XXX max number of CPUS?

/* Translated blocks */
static GPtrArray *blocks;

const uint64_t fnv_prime = 0x100000001b3ULL;

static void printf_el(gpointer data, gpointer user_data)
{
    bb_entry_t *bb = (bb_entry_t *)data;
    if (bb->exec && bb->offset != -1) {
        //fprintf(fp, "%lx\n", bb->hash);
        fprintf(fp, "%s + %x \n", bb->mod, bb->offset);
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

bool in_vma_loop = false;

typedef struct vma {
  uint32_t vma_start;
  uint32_t vma_end;
  char filename[64];
} vma;

typedef struct proc {
  uint32_t pid;
  uint32_t ppid;
  uint32_t create_time;
  char comm[16];
  std::vector<vma*> vmas;
} proc;


proc current_proc;
vma* current_vma;

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    if (qemu_plugin_in_privileged_mode()) 
      return;

    bb_entry_t *bb = (bb_entry_t *) udata;
    g_mutex_lock(&lock);
    bb->exec = true;
    g_mutex_unlock(&lock);

    for (auto &&e : current_proc.vmas) {
      if (bb->start >= e->vma_start && bb->start < e->vma_end) {
        //printf("%s (%d) hit block at %s + %x\n", current_proc.comm, current_proc.pid, e->filename, bb->start - e->vma_start);
        g_mutex_lock(&lock);
        strncpy(bb->mod, current_proc.comm, sizeof(bb->mod));
        bb->offset = bb->start - e->vma_start;
        g_mutex_unlock(&lock);
        break;
      }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    bb_entry_t *bb = g_new0(bb_entry_t, 1);
#if 0
    size_t n = qemu_plugin_tb_n_insns(tb);
    // fnv hashing: https://www.programmingalgorithms.com/algorithm/fnv-hash/c/
    // and https://github.com/haipome/fnv/blob/master/fnv.c
    uint64_t hash = 0;

    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        hash *= fnv_prime;

        // Get raw bytes in a large container
        uint64_t insn_bytes  = *(uint64_t*)qemu_plugin_insn_data(insn);
        size_t insn_size = qemu_plugin_insn_size(insn);
        //bb->size += insn_size

        // If I were good at math there'd be a cleaner way. Compiler should optimize?
        for (size_t i=64/8; i >= insn_size; i--) {
          ((char*)&insn_bytes)[i] = 0;
        }
        hash ^= insn_bytes;
    }
    bb->hash = hash;
#endif

    bb->start = pc;
    bb->mod[0] = char(0);
    bb->offset = -1;
    bb->exec = false;

    g_mutex_lock(&lock);
    g_ptr_array_add(blocks, bb);
    g_mutex_unlock(&lock);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)bb);
}

void vcpu_hypercall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t a1, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {

  switch(num) {
    /// PROCESS SWITCH ///
    case 590: {
      // Process switch starts with reporting  name
      current_proc = {0};
      if (qemu_plugin_read_guest_virt_mem(a1, &current_proc.comm, sizeof(current_proc.comm)) == -1) {
        strncpy(current_proc.comm, "[error]", sizeof(current_proc.comm));
      }
      break;
    }

    case 591: // PID (TGID edition)
      current_proc.pid = (uint32_t)a1;
      break;

    case 592: // PPID
      current_proc.ppid = (uint32_t)a1;

    case 593: // create time
      current_proc.create_time = (uint32_t)a1;

      // End of process switch: let's log it
      //printf("Swithed to process %s with PID %d and PPID %d\n", current_proc.comm, current_proc.pid, current_proc.ppid);
      break;


    /// VMA LOOP ////
    case 5910: // start, step, and finish VMA loop
      if (a1 == 0 && !in_vma_loop) {
        // Starting
        in_vma_loop = true;
        current_proc.vmas.clear(); // Always clear VMAs for current on VMA update

        // Allocate first
        current_vma = (struct vma*)malloc(sizeof(vma));
        current_vma->filename[0] = (char)0;

      } else if (a1 == 2 && in_vma_loop) {
        // Finished
        in_vma_loop = false;

        //for (auto &&e : current_proc.vmas) {
        //  printf("In %s (%d): VMA named %s goes from %x to %x\n", current_proc.comm, current_proc.pid, e->filename, e->vma_start, e->vma_end);
        //}

      } else if (a1 == 1 && in_vma_loop) {
        // Finished a VMA
        // Move current vma into list and allocate a new one
        current_proc.vmas.push_back(current_vma);

        // Allocate first
        current_vma = (struct vma*)malloc(sizeof(vma));

      } else {
        printf("ERROR: vma_loop_toggle %ld with in_vma_loop=%d\n", a1, in_vma_loop);
        assert(0);
      }

      break;

    case 5911: {
      current_vma->vma_start = (uint32_t)a1;
      break;
      }

    case 5912:
      current_vma->vma_end = (uint32_t)a1;
      break;

    case 5913: {
        if (qemu_plugin_read_guest_virt_mem(a1, &current_vma->filename, sizeof(current_vma->filename)) == -1) {
          strncpy(current_vma->filename, "[error]", sizeof(current_vma->filename));
        }
      break;
      }

    case 5914:
      if (a1 == 1)
        strncpy(current_vma->filename, "[heap]", sizeof(current_vma->filename));
      else if (a1 == 2)
        strncpy(current_vma->filename, "[stack]", sizeof(current_vma->filename));
      else if (a1 == 3)
        strncpy(current_vma->filename, "[???]", sizeof(current_vma->filename));
      break;

    default:
      printf("ERROR: unknown hypercall number %ld with arg %lx\n", num, a1);
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

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_hypercall_cb(id, vcpu_hypercall);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
