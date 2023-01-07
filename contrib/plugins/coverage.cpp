#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

static const char *covfile = "coverage.map";
static const char *bindfile = "vpn.csv";

static GMutex lock;
//const uint64_t fnv_prime = 0x100000001b3ULL;
const uint32_t fnv_prime = 0x811C9DC5;

#define MAP_SIZE 0xffffff
static char *shared_mem;

/*
 * Process map: (pid, create) -> Process(name, blocks, active_vmas, last_pc)
 * Block details: start, size, module, offset, exec
 *
 */

typedef struct {
  uint32_t vma_start;
  uint32_t vma_end;
  char filename[64];
} vma_t;

typedef struct {
  uint32_t pid;
  uint32_t type;
  uint32_t ipv; // 4 or 6
  char ip_addr[64]; // 1.2.3.4, 1:2:3:...
  uint32_t port;
} bind_t;

typedef struct {
    uint32_t start;
    uint32_t size;
    //char mod[64]; // TODO use an ID into all modules?
    //uint32_t offset;
    //bool     exec;
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
  char comm[64];
  bool ignore;
  //uint32_t comm_hash;
  std::vector<vma_t*>* vmas;
  //std::set<bb_entry_t*, block_cmp>* blocks;
  uint32_t prev_location;

  uint32_t last_bb_end;
  uint32_t last_bb_start;
} proc_t;

struct hash_tuple {
  //https://www.geeksforgeeks.org/how-to-create-an-unordered_map-of-tuples-in-c/
  template <class T1, class T2>
    size_t operator()(const std::tuple<T1, T2>& x) const {
      return std::get<0>(x) ^ std::get<1>(x);
    }
};

// If this isn't on the heap it will vanish before our plugin_exit is called. Ugh!
std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple> *proc_map = \
    new std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple>;

uint32_t hash(char *input) {
    uint32_t rv = 0;
    for (size_t i=0; i < strlen(input); i++) {
      rv *= fnv_prime;
      rv ^= (uint32_t)input[i];
    }

    return rv;
}

int find_open_port() {
  // https://stackoverflow.com/a/20850182
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  assert(sock >= 0);

  struct sockaddr_in serv_addr;
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = 0;
  if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
    perror("Error finding free port");
    return -1;
  }

  socklen_t len = sizeof(serv_addr);
  if (getsockname(sock, (struct sockaddr *)&serv_addr, &len) == -1) {
    perror("Error finding free port name");
    return -1;
  }

  if (close (sock) < 0 ) {
    perror("Error cleaning up in find free port");
    return -1;
  }

  return ntohs(serv_addr.sin_port);

}

void report_bind(bind_t pending_bind) {
    if (pending_bind.type >= 2) {
      printf("ERROR: unknown protocol: %d\n", pending_bind.type);
      return;
    }

    FILE *f = fopen(bindfile, "a");
    int host_port = find_open_port();

    assert(host_port > 0);

    //(f"{proto},{listen_ip}:{listen_port},0.0.0.0:{host_port}\n")
    if (pending_bind.ipv == 4) {
      fprintf(f, "%s,%s:%d,0.0.0.0:%d\n",
        /*proto*/ (pending_bind.type == 0) ? "tcp" : "udp",
        /*ipv4*/ pending_bind.ip_addr,
        /*port*/ pending_bind.port,
        /*host port*/ host_port);
    } else {
      // Ipv6
      fprintf(f, "%s,[%s]:%d,0.0.0.0:%d\n",
        /*proto*/ (pending_bind.type == 0) ? "tcp" : "udp",
        /*ipv4*/ pending_bind.ip_addr,
        /*port*/ pending_bind.port,
        /*host port*/ host_port);
    }

    fclose(f);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    FILE *f = fopen(covfile, "wb");
    fwrite(shared_mem, 1, MAP_SIZE, f);
    fclose(f);


#if 0
    for (auto& k : *proc_map) {
      proc_t *p = k.second;
      for (auto bb : *p->blocks) {
        if (bb->exec) {
          fprintf(fp, "%s (%d, %u) -> %s + %x\n", p->comm, p->pid, p->create_time, bb->mod, bb->offset);
        }
        g_free(bb);
      }
    }
    fclose(fp);
#endif
}

proc_t *current_proc;
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    if (qemu_plugin_in_privileged_mode())
      return;

    if (!current_proc) return; // Start up: no idea where we are (unexpected that we'd get here?)
    if (current_proc->ignore) return; // Start up: no idea where we are (unexpected that we'd get here?)

    bb_entry_t *bb = (bb_entry_t *) udata;

    // If we're re-executing the end of the last block, bail
    if (bb->start >= current_proc->last_bb_start && bb->start < current_proc->last_bb_end)
      return;

    current_proc->last_bb_start = bb->start;
    current_proc->last_bb_end = bb->start+bb->size;

    for (auto &&e : *current_proc->vmas) {
      if (bb->start >= e->vma_start && bb->start < e->vma_end) {
       // HIT! We're at a relative offset to some region we know of
       uint32_t offset = bb->start - e->vma_start;

       // https://github.com/AFLplusplus/AFLplusplus/blob/stable/frida_mode/MapDensity.md
       // Do we want to always hash in filename? It will be kind of expensive?
       uint32_t cur_location = hash(e->filename) ^ ((offset >> 4) ^ (offset << 8));

#if 0
       printf("HASH %x at  %s + %x\n",
              (cur_location ^ current_proc->prev_location) % MAP_SIZE,
              e->filename, offset);
        printf("\tcur_location = %x\n", cur_location);
        printf("\tprev_location = %x\n", current_proc->prev_location);
#endif

        //printf("\t%s hashes to %x\n\toffset >> 4 is %x\t offset << 8 is %x\n", e->filename, hash(e->filename), offset >>4, offset << 8);
        //printf("\toffset >> 4 ^ offset << 8 is %x\n", (offset >>4) ^ (offset << 8));

       shared_mem[(cur_location ^ current_proc->prev_location) % MAP_SIZE]++;
       current_proc->prev_location = cur_location >> 1;

#if 0
        g_mutex_lock(&lock);
        // XXX we only mark the block as "executed" if we know where it executed.
        // Maybe this is a bad design, but otherwise we see a lot of -1s for offset
        bb->exec = true;

        strncpy(bb->mod, e->filename, sizeof(bb->mod)); // Segment we're relative to
        bb->offset = bb->start - e->vma_start;
        g_mutex_unlock(&lock);
        //printf("%s (%d) hit block at %s + %x\n", current_proc->comm, current_proc->pid, bb->mod, bb->offset);
#endif
        break;
      }
    }
    // Note we can't free BB since this callback will be run multiple times
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    if (!current_proc) return; // Start up: no idea where we are
    uint64_t pc = qemu_plugin_tb_vaddr(tb);

#if 0
    for (auto oldbb : *current_proc->blocks) { // XXX this is probably a bit slow!
      if (pc > oldbb->start && pc < oldbb->start + oldbb->size)
        return;
    }
#endif

    size_t n = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn* last_insn = qemu_plugin_tb_get_insn(tb, n-1);
    uint32_t size = (qemu_plugin_insn_vaddr(last_insn) + qemu_plugin_insn_size(last_insn)) - pc;

    bb_entry_t *bb = g_new0(bb_entry_t, 1);
    bb->start = pc;
    bb->size = size;
    //bb->mod[0] = char(0);
    //bb->offset = -1;
    //bb->exec = false;

    //g_mutex_lock(&lock);
    //current_proc->blocks->insert(bb);
    //g_mutex_unlock(&lock);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)bb);
}

bool in_vma_loop = false;

proc_t pending_proc;
vma_t* pending_vma;
bind_t pending_bind;

void vcpu_hypercall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t a1, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {

  switch (num) {
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
      break;

    case 593: // create time
      pending_proc.create_time = (uint32_t)a1;
      break;

    case 594: { // is/isn't kernel thread (end of create proc)
      pending_proc.ignore = (a1 != 0);

      auto k = std::make_tuple(pending_proc.pid, pending_proc.create_time);
      if (proc_map->find(k) == proc_map->end()) {
        // Insert into proc map if we the process we're switching to isn't in there already
        g_mutex_lock(&lock);
        (*proc_map)[k] = (proc_t*)malloc(sizeof(proc_t));
        (*proc_map)[k]->pid = pending_proc.pid;
        (*proc_map)[k]->ignore = pending_proc.ignore;
        (*proc_map)[k]->ppid = pending_proc.ppid;
        (*proc_map)[k]->create_time = pending_proc.create_time;
        (*proc_map)[k]->vmas = new std::vector<vma_t*>;
        (*proc_map)[k]->prev_location = hash(pending_proc.comm);
        //(*proc_map)[k]->blocks = new std::set<bb_entry_t*, block_cmp>;
        strncpy((*proc_map)[k]->comm, pending_proc.comm, sizeof((*proc_map)[k]->comm));
        g_mutex_unlock(&lock);
      }
      // Update current proc
      current_proc = (*proc_map)[k];
      // End of process switch: let's log it
      //if (!current_proc->ignore)
      //  printf("Swithed to process %s with PID %d and PPID %d\n", pending_proc.comm, pending_proc.pid,
      //                                                            pending_proc.ppid);
      break;
    }

    case 595: // update proc name: kernel task
    case 596: { // update proc name: non-kernel task
      // Don't reset current_proc, just modify its name in place
      if (current_proc != NULL) {
        if (qemu_plugin_read_guest_virt_mem(a1, &current_proc->comm, sizeof(current_proc->comm)) != -1) {
          current_proc->prev_location = hash(current_proc->comm); // Deterministically reset hash state since we're in a new program now
        }
        current_proc->ignore = (num == 595); // Ignore if kernel task, otherwise don't
      }
    }

    /// VMA LOOP. Populate pending_vma, then add to current_proc->vmas ////
    case 5910: // start, step, and finish VMA loop
      if (current_proc != NULL) {
        if (a1 == 1 && !in_vma_loop) { // Starting
          in_vma_loop = true;
          current_proc->vmas->clear(); // Always clear VMAs for current proc on VMA update
          pending_vma = new vma_t;

        } else if (a1 == 3 && in_vma_loop) {
          in_vma_loop = false;
          //for (auto &e : current_proc->vmas) {
          //  printf("In %s (%d): VMA named %s goes from %x to %x\n", current_proc->comm, current_proc->pid, e->filename, e->vma_start, e->vma_end);
          //}

        } else if (a1 == 2 && in_vma_loop) {
          // Finished a VMA
          g_mutex_lock(&lock);
          current_proc->vmas->push_back(pending_vma); // Move current vma into list and allocate a new one
          g_mutex_unlock(&lock);

          // Allocate a new one
          pending_vma = new vma_t;

        } else {
          printf("ERROR: vma_loop_toggle %ld with in_vma_loop=%d\n", a1, in_vma_loop);
        }
      }

      break;

    case 5911: {
      if (in_vma_loop) {
        pending_vma->vma_start = (uint32_t)a1;
      }
      break;
      }

    case 5912:
      if (in_vma_loop) {
        pending_vma->vma_end = (uint32_t)a1;
      }
      break;

    case 5913: {
      if (in_vma_loop) {
        if (qemu_plugin_read_guest_virt_mem(a1, &pending_vma->filename, sizeof(pending_vma->filename)) == -1) {
          strncpy(pending_vma->filename, "[error]", sizeof(pending_vma->filename));
        }
      }
      break;
      }

    case 5914:
      if (in_vma_loop) {
        if (a1 == 1)
          strncpy(pending_vma->filename, "[heap]", sizeof(pending_vma->filename));
        else if (a1 == 2)
          strncpy(pending_vma->filename, "[stack]", sizeof(pending_vma->filename));
        else if (a1 == 3)
          strncpy(pending_vma->filename, "[???]", sizeof(pending_vma->filename));
      }
      break;


    /// NETWORK, fill pending_bind ///
    case 5930: // Start. PID
      pending_bind = {0};
      pending_bind.pid = a1;
      break;

    case 5931: // Type
      pending_bind.type = a1; // Type: 0=SOCK_STREAM, 1=SOCK_DGRAM, 2=other
      if (a1 > 3) {
        printf("ERROR bad ip type. HAVE: pid %d, ipv %d, type %d, ip_addr %s, port %d\n", pending_bind.pid, pending_bind.ipv, pending_bind.type, pending_bind.ip_addr, pending_bind.port);
      }
      break;

    case 5932: // IPv4 address
    case 5933: // IPv6 address
        pending_bind.ipv = (num == 5932) ? 4 : 6;
        if (qemu_plugin_read_guest_virt_mem(a1, &pending_bind.ip_addr, sizeof(pending_bind.ip_addr)) == -1) {
          strncpy(pending_bind.ip_addr, "[error]", sizeof(pending_bind.ip_addr));
        }
      break;

    case 5934:
      pending_bind.port = a1;
      // All done
      report_bind(pending_bind);
      break;

    /// In-guest driver ///
    case 6001: { // Guest is ready for data
      uint64_t gva = (uint64_t)a1;

      // Do we want to fuzz something? We probably should, if not, what are we doing here?
      char payload[] = {"\x02" "AAAAAAA"};

      // Guest should keep retrying quickly so when we restore the snapshot it's good to go!
      if (qemu_plugin_write_guest_virt_mem(gva, &payload, sizeof(payload)) == -1) {
        printf("ERROR couldn't send in data: GVA %#lx\n", gva);
      }
      break;
    }

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
        if (g_strcmp0(tokens[0], "covfile") == 0) {
            //file_name = g_strdup(tokens[1]);
            covfile = g_strdup(tokens[1]);
        }
        if (g_strcmp0(tokens[0], "bindfile") == 0) {
            //file_name = g_strdup(tokens[1]);
            bindfile = g_strdup(tokens[1]);
            fclose(fopen(bindfile, "w")); // Empty file
        }
    }

    shared_mem = (char*)malloc(MAP_SIZE);
    if (shared_mem == NULL) {
      printf("Unable to allocate memory\n");
      return 1;
    }

    //fp = fopen(file_name, "wb");
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_hypercall_cb(id, vcpu_hypercall);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
