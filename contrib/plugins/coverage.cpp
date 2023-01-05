#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <vector>
#include <tuple>
#include <set>
#include <unordered_map>

extern "C" {
#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "coverage";
#include <plugin-qpp.h>
}

static FILE *fp;
static const char *file_name = "file.trace";
static GMutex lock;

/*
 * Process map: (pid, create) -> Process(name, blocks, active_vmas, last_pc)
 * Block details: start, size, module, offset, exec
 *
 * (NYI) All modules: [name, start_end, filename] -> (process id, process create time)
 */

typedef struct {
  uint32_t vma_start;
  uint32_t vma_end;
  char filename[64];
} vma_t;

typedef struct {
    uint32_t start;
    uint32_t size;
    char mod[64]; // TODO use an ID into all modules?
    uint32_t offset;
    bool     exec;
} bb_entry_t;


struct block_cmp {
  bool operator() (bb_entry_t *a, bb_entry_t *b) const {
    return a->start < b->start;
  }
};

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint32_t create_time;
  char comm[16];
  std::vector<vma_t*>* vmas;
  //std::vector<bb_entry_t*>* blocks;
  std::set<bb_entry_t*, block_cmp>* blocks;
} proc_t;

struct hash_tuple {
  //https://www.geeksforgeeks.org/how-to-create-an-unordered_map-of-tuples-in-c/
  template <class T1, class T2>
    size_t operator()(const std::tuple<T1, T2>& x) const {
      return std::get<0>(x) ^ std::get<1>(x);
    }
};

// If this isn't on the heap it will vanish before our plugin_exit is called
std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple> *proc_map = new std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple>;

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    for (auto& k : *proc_map) {
      for (auto bb : *k.second->blocks) {
        if (bb->exec) {
          fprintf(fp, "%s -> %s + %x\n", k.second->comm, bb->mod, bb->offset);
        }
        g_free(bb);
      }
    }

    fclose(fp);
}

proc_t *current_proc;
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    if (qemu_plugin_in_privileged_mode()) 
      return;

    if (!current_proc) return; // Start up: no idea where we are (unexpected that we'd get here?)

    bb_entry_t *bb = (bb_entry_t *) udata;

    for (auto &&e : *current_proc->vmas) {
      if (bb->start >= e->vma_start && bb->start < e->vma_end) {
        g_mutex_lock(&lock);

        // XXX we only mark the block as "executed" if we know where it executed.
        // Maybe this is a bad design, but otherwise we see a lot of -1s for offset
        bb->exec = true;

        strncpy(bb->mod, e->filename, sizeof(bb->mod)); // Segment we're relative to
        bb->offset = bb->start - e->vma_start;
        g_mutex_unlock(&lock);
        //printf("%s (%d) hit block at %s + %x\n", current_proc->comm, current_proc->pid, bb->mod, bb->offset);
        break;
      }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    if (!current_proc) return; // Start up: no idea where we are
    uint64_t pc = qemu_plugin_tb_vaddr(tb);

    // Check if this BB is a subset of a prior BB - if so bail!
    for (auto oldbb : *current_proc->blocks) { // XXX INEFFICIENT
      if (pc > oldbb->start && pc < oldbb->start + oldbb->size)
        return;
    }

    size_t n = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn* last_insn = qemu_plugin_tb_get_insn(tb, n-1);
    uint32_t size = (qemu_plugin_insn_vaddr(last_insn) + qemu_plugin_insn_size(last_insn)) - pc;

    bb_entry_t *bb = g_new0(bb_entry_t, 1);
    bb->start = pc;
    bb->size = size;
    bb->mod[0] = char(0);
    bb->offset = -1;
    bb->exec = false;

    g_mutex_lock(&lock);
    //current_proc->blocks->push_back(bb);
    current_proc->blocks->insert(bb);
    g_mutex_unlock(&lock);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)bb);
}

bool in_vma_loop = false;

proc_t pending_proc;
vma_t* pending_vma;

void vcpu_hypercall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t a1, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {

  switch(num) {
    /// PROCESS SWITCH. Build pending_proc ///
    case 590: {
      // Process switch starts with reporting  name
      pending_proc = {0};
      if (qemu_plugin_read_guest_virt_mem(a1, &pending_proc.comm, sizeof(pending_proc.comm)) == -1) {
        strncpy(pending_proc.comm, "[error]", sizeof(pending_proc.comm));
      }
      break;
    }

    case 591: // PID (TGID edition)
      pending_proc.pid = (uint32_t)a1;
      break;

    case 592: // PPID
      pending_proc.ppid = (uint32_t)a1;

    case 593: { // create time
      pending_proc.create_time = (uint32_t)a1;

      auto k = std::make_tuple(pending_proc.pid, pending_proc.create_time);
      if (proc_map->find(k) == proc_map->end()) {
        // Insert into proc map if we the process we're switching to isn't in there already
        g_mutex_lock(&lock);
        (*proc_map)[k] = (proc_t*)malloc(sizeof(proc_t));
        (*proc_map)[k]->pid = pending_proc.pid;
        (*proc_map)[k]->ppid = pending_proc.ppid;
        (*proc_map)[k]->create_time = pending_proc.create_time;
        (*proc_map)[k]->vmas = new std::vector<vma_t*>;
        //(*proc_map)[k]->blocks = new std::vector<bb_entry_t*>;
        (*proc_map)[k]->blocks = new std::set<bb_entry_t*, block_cmp>;
        strncpy((*proc_map)[k]->comm, pending_proc.comm, sizeof((*proc_map)[k]->comm));
        g_mutex_unlock(&lock);
      }
      // Update current proc
      current_proc = (*proc_map)[k];
      //printf("proc is now %s\n", current_proc->comm);

      // End of process switch: let's log it
      //printf("Swithed to process %s with PID %d and PPID %d\n", pending_proc.comm, pending_proc.pid, pending_proc.ppid);
      break;
    }


    /// VMA LOOP. Populate pending_vma, then add to current_proc->vmas ////
    case 5910: // start, step, and finish VMA loop
      if (a1 == 0 && !in_vma_loop) { // Starting
        in_vma_loop = true;
        current_proc->vmas->clear(); // Always clear VMAs for current proc on VMA update
        pending_vma = new vma_t;

      } else if (a1 == 2 && in_vma_loop) {
        in_vma_loop = false;
        //for (auto &e : current_proc->vmas) {
        //  printf("In %s (%d): VMA named %s goes from %x to %x\n", current_proc->comm, current_proc->pid, e->filename, e->vma_start, e->vma_end);
        //}

      } else if (a1 == 1 && in_vma_loop) {
        // Finished a VMA
        g_mutex_lock(&lock);
        current_proc->vmas->push_back(pending_vma); // Move current vma into list and allocate a new one
        g_mutex_unlock(&lock);

        // Allocate a new one
        pending_vma = new vma_t;

      } else {
        printf("ERROR: vma_loop_toggle %ld with in_vma_loop=%d\n", a1, in_vma_loop);
        assert(0);
      }

      break;

    case 5911: {
      assert(in_vma_loop);
      pending_vma->vma_start = (uint32_t)a1;
      break;
      }

    case 5912:
      assert(in_vma_loop);
      pending_vma->vma_end = (uint32_t)a1;
      break;

    case 5913: {
        assert(in_vma_loop);
        if (qemu_plugin_read_guest_virt_mem(a1, &pending_vma->filename, sizeof(pending_vma->filename)) == -1) {
          strncpy(pending_vma->filename, "[error]", sizeof(pending_vma->filename));
        }
      break;
      }

    case 5914:
      assert(in_vma_loop);
      if (a1 == 1)
        strncpy(pending_vma->filename, "[heap]", sizeof(pending_vma->filename));
      else if (a1 == 2)
        strncpy(pending_vma->filename, "[stack]", sizeof(pending_vma->filename));
      else if (a1 == 3)
        strncpy(pending_vma->filename, "[???]", sizeof(pending_vma->filename));
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

    fp = fopen(file_name, "wb");
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_hypercall_cb(id, vcpu_hypercall);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
