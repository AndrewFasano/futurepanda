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

#include <algorithm>    // std::find
#include <string.h>
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

static const char *bindfile = "vpn.csv";
qemu_plugin_id_t self_id;

static GMutex lock;

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

struct service_t {
  uint32_t port;
  uint32_t proto;
  char ip_addr[64];
  char comm[64];
  bool snapped;

  //bool operator==(const service_t &other) const
  //{ return (port == other.port
  //          && proto == other.proto
  //          && strncmp(ip_addr, other.ip_addr, 64) == 0
  //          && strncmp(comm, other.comm, 64) == 0);
  //}

};

std::vector<service_t*>* launched_services = new std::vector<service_t*>;


bool main_loop_wait_active = false;

const uint32_t fnv_prime = 0x811C9DC5;
uint32_t hash(char *input) {
    uint32_t rv = 0;
    for (size_t i=0; i < strlen(input); i++) {
      rv *= fnv_prime;
      rv ^= (uint32_t)input[i];
    }
    return rv;
}

int snap_counter = 0;

void take_snap(qemu_plugin_id_t id, void* udata) {
  // XXX: Must run in main thread (i.e. with main loop callback)
  bool* active = (bool*)udata;
  if (*active) return;
  *active = true;

  // Take a snapshot with a unique name, mark everything in launched_services as snapped
  char snap_name[32];
  snprintf(snap_name, 32, "snap_%d", snap_counter++);

  //g_mutex_lock(&lock);
  for (auto service : *launched_services) {
    if (!service->snapped) {
      service->snapped = true; // Service is now snapped, well, it is in a sec
      printf("Snapshot %s is valid for service %s listening on %s:%d proto=%d\n", snap_name,
             service->comm, service->ip_addr, service->port, service->proto);
    }
  }
  //g_mutex_unlock(&lock);
  qemu_plugin_save_snapshot(snap_name, true);
  main_loop_wait_active = false;
}

proc_t *current_proc;

void report_bind(bind_t pending_bind, proc_t* binder) {
    if (pending_bind.type >= 2) {
      printf("ERROR: unknown protocol: %d\n", pending_bind.type);
      return;
    }

    if (binder == NULL) {
      printf("ERROR: Want to report bind, but current process is unknown\n");
      return;
    }

    // We know the snap_name: at this point we haven't yet saved the service
    // so when we next do, it will be at snap_counter
    char snap_name[32];
    snprintf(snap_name, 32, "snap_%d", snap_counter);

    FILE *f = fopen(bindfile, "a");

    if (pending_bind.ipv == 4) {
      // Proto, ip/[ipv6]:port, pid, proc_name
      fprintf(f, "%s,%s:%d,%d,%s,%s\n",
        /*proto*/ (pending_bind.type == 0) ? "tcp" : "udp",
        /*ipv4*/ pending_bind.ip_addr,
        /*port*/ pending_bind.port,
        /* pid */ binder->pid,
        /* proc_name */ binder->comm,
        /* snap name */ snap_name
        );
    } else {
      // Ipv6
      fprintf(f, "%s,[%s]:%d,%d,%s,%s\n",
        /*proto*/ (pending_bind.type == 0) ? "tcp" : "udp",
        /*ipv4*/ pending_bind.ip_addr,
        /*port*/ pending_bind.port,
        /* pid */ binder->pid,
        /* proc_name */ binder->comm,
        /* snap name */ snap_name
        );
    }

    fclose(f);

    // We've identified a process that we might want to snap

    service_t *details  = new service_t({
      .port = pending_bind.port,
      .proto = pending_bind.type,
    });
    strncpy(details->ip_addr, pending_bind.ip_addr, 64);
    strncpy(details->comm, binder->comm, 64);

    auto match = std::find(launched_services->begin(), launched_services->end(), details);
    if (match == launched_services->end()) {
      // New service - let's add it, not yet snapshot
      launched_services->push_back(details);
    }
}

proc_t pending_proc;
bind_t pending_bind;

void vcpu_hypercall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t a1, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {

  switch (num) {
    /// PROCESS SWITCH. Build pending_proc ///
    case 590: // Process switch starts with reporting  name
      pending_proc = {0};
      if (qemu_plugin_read_guest_virt_mem(a1, &pending_proc.comm, sizeof(pending_proc.comm)) == -1) {
        strncpy(pending_proc.comm, "[error]", sizeof(pending_proc.comm));
      }
      break;

    case 591: // PID (TGID edition)
      pending_proc.pid = (uint32_t)a1;
      break;

    case 592: // PPID
      pending_proc.ppid = (uint32_t)a1;
      break;

    case 593: // create time
      pending_proc.create_time = (uint32_t)a1;
      break;

    case 594: { // Is/isn't kernel thread. Update proc_map & set current_pro
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
        //(*proc_map)[k]->vmas = new std::vector<vma_t*>;
        //(*proc_map)[k]->prev_location = hash(pending_proc.comm);
        //(*proc_map)[k]->blocks = new std::set<bb_entry_t*, block_cmp>;
        strncpy((*proc_map)[k]->comm, pending_proc.comm, sizeof((*proc_map)[k]->comm));
        g_mutex_unlock(&lock);
      }
      current_proc = (*proc_map)[k];
      break;
    }

    case 595: // update proc name: kernel task
    case 596: // update proc name: non-kernel task
      // Don't reset current_proc, just modify its name in place
      if (current_proc != NULL) {
        if (qemu_plugin_read_guest_virt_mem(a1, &current_proc->comm, sizeof(current_proc->comm)) != -1) {
          //current_proc->prev_location = hash(current_proc->comm); // Deterministically reset hash state since we're in a new program now
        }
        current_proc->ignore = (num == 595); // Ignore if kernel task, otherwise don't
      }

    // VMAs: We don't care
    case 5910:
    case 5911:
    case 5912:
    case 5913:
    case 5914:
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

    case 5934: // Set port, report bind
      pending_bind.port = a1;
      report_bind(pending_bind, current_proc);
      break;


    /// In-guest driver ///
    case 6001: { // Guest is ready for data
      uint64_t gva = (uint64_t)a1;

      // We have three possible responses that we'll send
      // 1) 0: Go to sleep for a bit, no imminent data
      // 2) 1: Don't sleep but retry (immininent data)
      // 3) 2: Here's some data + metadata + 1024 byte message
      char sleep[] = {"\x00"};
      char retry[] = {"\x01"};

      // If we have any pending snapshots: reply 1 and queue snapshot
      //
      // We have two states within pending: First state is when we haven't
      // even queued the main_loop_wait. In this case we'll add it to the queue
      // and tell the guest agent to retry
      //
      // The second state is when we've queued it up but the snapshot isn't done
      // so we'll tell the guest agent to retry without re-adding to queueu

      g_mutex_lock(&lock);
      if (!main_loop_wait_active) {
        // Don't have anything queued up for the next main loop wait.
        // But if there are any new services, we should queue it up
        for (auto service : *launched_services) {
          if (!service->snapped) {
            main_loop_wait_active = true;
            bool* active = new bool;
            *active = false;
            qemu_plugin_register_main_loop_cb(self_id, &take_snap, &active);
          }
        }
      }
      g_mutex_unlock(&lock);

      if (main_loop_wait_active) {
        // Guest should keep retrying quickly so when we restore the snapshot it's good to go!
        if (qemu_plugin_write_guest_virt_mem(gva, &retry, sizeof(retry)) == -1) {
          printf("ERROR couldn't send in data: GVA %#lx\n", gva);
        }

      } else {
        // In this plugin we never have data to send - we just take opportunistic snapshots. So if no snapshots are pending
        // tell the guest driver to chill
        if (qemu_plugin_write_guest_virt_mem(gva, &sleep, sizeof(sleep)) == -1) {
          printf("ERROR couldn't send in data: GVA %#lx\n", gva);
        }
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
        if (g_strcmp0(tokens[0], "bindfile") == 0) {
            bindfile = g_strdup(tokens[1]);
        }
    }

    fclose(fopen(bindfile, "w")); // Empty file

    self_id = id;
    qemu_plugin_register_vcpu_hypercall_cb(id, vcpu_hypercall);
    return 0;
}
